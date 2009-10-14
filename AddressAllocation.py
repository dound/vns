"""Handles allocating IP blocks."""

import logging
import math
import random
from socket import inet_aton, inet_ntoa
import struct

import web.vnswww.models as db

def instantiate_template(owner, template, ip_block_from, src_filters):
    """Instantiates a new Topology object, allocates a block of addresses for
    it, and assigns addresses to each port in it.  The block will come from
    ip_block_from.  The topology will be assigned the specified source filters.
    A tuple is returned -- if the first element is not None, then an error has
    occurred and nothing was instantiated (the first element is an error
    message).  Otherwise, elements 2-4 are the Topology, IPBlockAllocation, and
    PortTreeNode root node objects."""
    # build a depth-first "tree" of the topology from the port connected to the gateway
    root = template.get_root_port()
    if not root:
        return ("template '%s' has no ports" % template.name,)
    tree = root.get_tree()
    num_addrs = tree.compute_subnet_size()

    # allocate a subblock of IPs for the new topology
    allocs = allocate_ip_block(ip_block_from, 1, num_addrs, src_filters)
    if not allocs:
        return ("insufficient free IP addresses",)
    alloc = allocs[0]

    # create the topology and assign IP addresses
    start_addr = struct.unpack('>I', inet_aton(alloc.start_addr))[0]
    assignments = tree.assign_addr(start_addr, alloc.size())
    t = db.Topology()
    t.owner = owner
    t.template = template
    t.enabled = True
    t.public = False
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

    return (None, t, alloc, tree)

def allocate_ip_block(block_from, num_blocks_to_alloc, num_addrs_per_block, src_filters):
    """Finds and allocates num_blocks_to_alloc block(s) each of size
    num_addrs_per_block.  A list of IPBlockAllocation records are returned.  The
    list will have the number of blocks which were able to be successfully
    allocated -- this will be less than num_blocks_to_alloc only if there is
    insufficient address space available to allocate that many blocks."""
    # round num_addrs_needed up to the closest power of 2
    min_block_mask_bits = 32 - int(math.ceil(math.log(num_addrs_per_block, 2)))
    return __allocate_ip_block(block_from, num_blocks_to_alloc, min_block_mask_bits, src_filters)

def __allocate_ip_block(block_from, num_blocks_to_alloc, min_block_mask_bits, src_filters):
    # find the allocations we need to workaround to avoid collisions ("allocations of concern")
    db_allocs = db.IPBlockAllocation.objects.filter(block_from=block_from)
    allocations = [(__str_ip_to_int(a.start_addr), a.mask) for a in db_allocs]
    ip_mask_list = [(__str_ip_to_int(sf.ip), sf.mask) for sf in src_filters]
    aoc = filter(lambda alloc : __allocs_filter(alloc, ip_mask_list), allocations)

    # add fake start and end usages so we can allocate blocks on the edges too
    block_from_start_addr = __str_ip_to_int(block_from.subnet)
    aoc.insert(0, (block_from_start_addr-1, 32)) # "use" last addr before block_from
    block_from_end_addr_plus_1 = block_from_start_addr + 2 ** (32 - block_from.mask)
    aoc.append((block_from_end_addr_plus_1, 32)) # "use" first addr after block_from

    # randomize the order in which we consider allocations => less likely to
    # reallocate a block soon after it is deallocated => user who wants to reuse
    # a particular IP block should be able to more often
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
        if num_addrs_avail >= num_addrs_needed:
            # if we're not too worried about fragmentation, then choose from
            # among the possible sub-blocks in this block
            max_offset = num_addrs_avail / num_addrs_needed
            offset = random.randint(1, max_offset)
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

def __str_ip_to_int(str_ip):
    """Converts a string to an IP address and returns the associated int value."""
    return struct.unpack('>I', inet_aton(str_ip))[0]
