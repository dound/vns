"""Handles allocating IP blocks."""

import logging
import math
import random
from socket import inet_aton, inet_ntoa
import struct

import web.vnswww.models as db

def free_topology(tid):
    """Deletes the topology associated with tid, as well as any IPAssignment,
    MACAssignment, TopologySourceIPFilter, TopologyUserFilter, and
    IPBlockAllocation objects belonging to it."""
    try:
        topo = db.Topology.objects.get(pk=tid)
        db.TopologySourceIPFilter.objects.filter(topology=topo).delete()
        db.TopologyUserFilter.objects.filter(topology=topo).delete()
        db.IPAssignment.objects.filter(topology=topo).delete()
        db.MACAssignment.objects.filter(topology=topo).delete()
        db.IPBlockAllocation.objects.filter(topology=topo).delete()
        topo.delete()
        logging.info('freed topology %d' % tid)
    except db.Topology.DoesNotExist:
        logging.warning('asked to free non-existent topology %d' % tid)

def instantiate_template(owner, template, ip_block_from, src_filters, temporary,
                         use_recent_alloc_logic=True, public=False,
                         use_first_available=False):
    """Instantiates a new Topology object, allocates a block of addresses for
    it, and assigns addresses to each port in it.  The block will come from
    ip_block_from.  The topology will be assigned the specified source filters.
    If use_first_available is True, then the first available block will be used.
    Otherwise, a random available block will be used.  The latter is generally
    better suited to temporary allocations (ones that only last a short time).
    A tuple is returned -- if the first element is not None, then an error has
    occurred and nothing was instantiated (the first element is an error
    message).  Otherwise, elements 2-4 are the Topology, IPBlockAllocation, and
    PortTreeNode root node objects."""
    # build a depth-first "tree" of the topology from the port connected to the gateway
    root = template.get_root_port()
    if not root:
        return ("template '%s' has no ports" % template.name,)
    try:
        tree = root.get_tree(True)
        num_addrs = tree.compute_subnet_size()
    except:
        # topology graph has cycles - just make each link its own /31
        tree = None
        links = db.Link.objects.filter(port1__node__template=template)
        num_addrs = len(links) * 2

    # try to give the user the allocation they most recently had
    alloc = __realloc_if_available(owner, template, ip_block_from) if use_recent_alloc_logic else None
    if not alloc:
        # allocate a subblock of IPs for the new topology
        allocs = allocate_ip_block(ip_block_from, 1, num_addrs, src_filters, use_first_available)
        if not allocs:
            return ("insufficient free IP addresses",)
        alloc = allocs[0]

    # create the topology and assign IP addresses
    start_addr = struct.unpack('>I', inet_aton(alloc.start_addr))[0]
    if tree:
        assignments = tree.assign_addr(start_addr, alloc.size())
    else:
        assignments = []
        for i,link in enumerate(links):
            assignments.append((link.port1, start_addr+2*i,   31))
            assignments.append((link.port2, start_addr+2*i+1, 31))

    t = db.Topology()
    t.owner = owner
    t.template = template
    t.enabled = True
    t.public = public
    t.temporary = temporary
    t.save()
    alloc.topology = t
    alloc.save()
    logging.info("Instantiated a new topology for %s from '%s': %s" % (owner, t.template.name, alloc))

    for sf_ip, sf_mask in src_filters:
        tsif = db.TopologySourceIPFilter()
        tsif.topology = t
        tsif.ip = sf_ip
        tsif.mask = sf_mask
        tsif.save()
        logging.info('IP source filter for new topology %d: %s' % (t.id, tsif))

    for port, ip, mask_sz in assignments:
        ipa = db.IPAssignment()
        ipa.topology = t
        ipa.port = port
        ipa.ip = inet_ntoa(struct.pack('>I', ip))
        ipa.mask = mask_sz
        ipa.save()
        logging.info('IP assignment for new topology %d: %s' % (t.id, ipa))

    # save the allocation as a "recent" allocation for this user
    if use_recent_alloc_logic:
        recent_alloc = db.RecentIPBlockAllocation()
        recent_alloc.user = owner
        recent_alloc.template = t.template
        recent_alloc.start_addr = alloc.start_addr
        recent_alloc.mask = alloc.mask
        recent_alloc.save()

    return (None, t, alloc, tree)

def allocate_ip_block(block_from, num_blocks_to_alloc, num_addrs_per_block, src_filters, use_first_available):
    """Finds and allocates num_blocks_to_alloc block(s) each of size
    num_addrs_per_block.  A list of IPBlockAllocation records are returned.  The
    list will have the number of blocks which were able to be successfully
    allocated -- this will be less than num_blocks_to_alloc only if there is
    insufficient address space available to allocate that many blocks."""
    # round num_addrs_needed up to the closest power of 2
    min_block_mask_bits = 32 - int(math.ceil(math.log(num_addrs_per_block, 2)))
    return __allocate_ip_block(block_from, num_blocks_to_alloc, min_block_mask_bits, src_filters, use_first_available)

def __allocate_ip_block(block_from, num_blocks_to_alloc, min_block_mask_bits, src_filters, use_first_available):
    # find the allocations we need to workaround to avoid collisions ("allocations of concern")
    db_allocs = db.IPBlockAllocation.objects.filter(block_from=block_from)
    allocations = [(__str_ip_to_int(a.start_addr), a.mask) for a in db_allocs]
    ip_mask_list = [(__str_ip_to_int(sf_ip), sf_mask) for sf_ip, sf_mask in src_filters]
    aoc = filter(lambda alloc : __allocs_filter(alloc, ip_mask_list), allocations)
    aoc.sort()

    # add fake start and end usages so we can allocate blocks on the edges too
    block_from_start_addr = __str_ip_to_int(block_from.subnet)
    aoc.insert(0, (block_from_start_addr-1, 32)) # "use" last addr before block_from
    block_from_end_addr_plus_1 = block_from_start_addr + 2 ** (32 - block_from.mask)
    aoc.append((block_from_end_addr_plus_1, 32)) # "use" first addr after block_from

    # randomize the order in which we consider allocations => less likely to
    # reallocate a block soon after it is deallocated => user who wants to reuse
    # a particular IP block should be able to more often
    if not use_first_available:
        split_index = random.randint(0, len(aoc)-1)
        aoc = aoc[split_index:] + aoc[:split_index + 1] # +1 => overlap so i,i+1 block is still checked

    # iterate over each adjacent pair of used block until a free segment
    # (between used blocks) is found
    new_allocations = []
    num_addrs_needed = 2 ** (32 - min_block_mask_bits)
    mask = 0xFFFFFFFF << (32 - min_block_mask_bits)
    for i in range(len(aoc) - 1):
        # compute the first address after this used block at which the subnet
        # can be allocated (i.e., align the start address to the subnet size)
        start_addr, num_masked_bits = aoc[i]
        sz = 2 ** (32 - num_masked_bits)
        faa = start_addr + sz # first available address
        aligned_faa = faa & mask
        if aligned_faa < faa:
            aligned_faa += num_addrs_needed # must start after the used block

        start_addr2, _ = aoc[i + 1]
        num_addrs_avail = start_addr2 - aligned_faa
        logging.debug('considering space b/w %s and %s => %d addresses available' % (__aoc_to_str(aoc[i]), __aoc_to_str(aoc[i+1]), num_addrs_avail))
        if num_addrs_avail >= num_addrs_needed:
            # if we're not too worried about fragmentation, then choose from
            # among the possible sub-blocks in this block
            if use_first_available:
                aligned_aa = aligned_faa
            else:
                max_offset = num_addrs_avail / num_addrs_needed
                offset = random.randint(0, max_offset-1)
                aligned_aa = aligned_faa + (num_addrs_needed * offset)

            # create the allocation
            new_alloc = db.IPBlockAllocation()
            new_alloc.block_from = block_from
            new_alloc.topology = None
            new_alloc.start_addr = inet_ntoa(struct.pack('>I', aligned_aa))
            new_alloc.mask = min_block_mask_bits
            new_alloc.save()
            logging.info('Allocated new block of addresses: %s' % new_alloc)
            new_allocations.append(new_alloc)
            if len(new_allocations) == num_blocks_to_alloc:
                return new_allocations # successfully allocated all requested blocks

    # failed to make all of the requested allocations -- insufficient address space
    logging.info('Not able to allocate %d blocks of %d addresses each: only got %d blocks' % (num_blocks_to_alloc, num_addrs_needed, len(new_allocations)))
    return new_allocations

def __allocs_filter(alloc, other_ip_mask_list):
    """Returns True if this any of the IP source filters associated with the
    topology using alloc overlaps with the IP source filters in other_ip_mask_list."""
    if not other_ip_mask_list:
        return True # empty list => 0/0 => overlaps with everything

    alloc_src_filters = db.TopologySourceIPFilter.objects.filter(topology=alloc.topology)
    if not alloc_src_filters:
        return True # empty list => 0/0 => overlaps with everything

    for asf in alloc_src_filters:
        if is_any_overlapping(__str_ip_to_int(asf.ip), asf.mask, other_ip_mask_list):
            return True
    return False

def is_overlapping(ip1, mask1_sz, ip2, mask2_sz):
    """Returns True if the two IP blocks overlap with each other.  The IPs
    should be 4B integers; the mask_sz variables should indicate the number of
    bits masked in the corresponding IP address."""
    mask1 = 0xFFFFFFFF << (32 - mask1_sz)
    mask2 = 0xFFFFFFFF << (32 - mask2_sz)
    combined_mask = mask1 & mask2 # e.g., use the smaller of the two
    return (ip1 & combined_mask) == (ip2 & combined_mask)

def is_any_overlapping(ip, num_masked_bits, ip_mask_list):
    """Returns True if ip/num_masked_bits overlaps with any of the ip/mask
    pairs in ip_mask_list."""
    for ip2_int, num_masked_bits2 in ip_mask_list:
        if is_overlapping(ip, num_masked_bits, ip2_int, num_masked_bits2):
            return True
    return False

def __realloc_if_available(owner, template, ip_block_from):
    """Checks to see if owner has previously allocated the specified template
    from ip_block_from.  If so, then previously allocated block is checked to
    see if it is available.  If so, then it is allocated and returned.
    Otherwise, None is returned.  Any record of a recent allocation is deleted."""
    recent_allocs = db.RecentIPBlockAllocation.objects.filter(user=owner, template=template)
    if recent_allocs:
        ra = recent_allocs[0]
        ret = __realloc_if_available_work(ra, ip_block_from)
        if ret:
            logging.info('Reallocated %s' % ra)
        else:
            logging.info('Unable to reallocate %s' % ra)
        recent_allocs.delete()
        return ret
    else:
        return None

def __realloc_if_available_work(ra, ip_block_from):
    # the recent allocation must be from the block we're trying to allocate from
    start_addr = struct.unpack('>I', inet_aton(ra.start_addr))[0]
    start_addr_from = struct.unpack('>I', inet_aton(ip_block_from.subnet))[0]
    if not is_overlapping(start_addr, ra.mask, start_addr_from, ip_block_from.mask):
        return None

    # the recent allocation must not be in use
    try:
        # does the closest active allocation BEFORE the recent alloc overlap it?
        closest_pre_alloc = db.IPBlockAllocation.objects.filter(start_addr__lte=ra.start_addr).order_by('-start_addr')[0]
        sa_pre = struct.unpack('>I', inet_aton(closest_pre_alloc.start_addr))[0]
        if is_overlapping(start_addr, ra.mask, sa_pre, closest_pre_alloc.mask):
            return None

        # does the closest active allocation AFTER to the recent alloc overlap it?
        closest_post_alloc = db.IPBlockAllocation.objects.filter(start_addr__gte=ra.start_addr).order_by('start_addr')[0]
        sa_post = struct.unpack('>I', inet_aton(closest_post_alloc.start_addr))[0]
        if is_overlapping(start_addr, ra.mask, sa_post, closest_post_alloc.mask):
            return None
    except IndexError:
        pass

    # it isn't in use => allocate it
    new_alloc = db.IPBlockAllocation()
    new_alloc.block_from = ip_block_from
    new_alloc.topology = None
    new_alloc.start_addr = ra.start_addr
    new_alloc.mask = ra.mask
    new_alloc.save()
    logging.info('RE-allocated new block of addresses: %s' % new_alloc)
    return new_alloc

def __str_ip_to_int(str_ip):
    """Converts a string to an IP address and returns the associated int value."""
    return struct.unpack('>I', inet_aton(str_ip))[0]

def __int_to_str_ip(int_ip):
    """Converts an int to the associated string representing an IP address."""
    return inet_ntoa(struct.pack('>I', int_ip))

def __aoc_to_str(aoc):
    """Converts an allocation of concern pair into an IP/mask string."""
    ip, mask = aoc
    return "%s/%d" % (__int_to_str_ip(ip), mask)