import math
import re

from django.contrib import messages
from django.contrib.auth.models import User
from django.core.exceptions import FieldError
from django.http import HttpResponse, HttpResponseRedirect
from django.db.models import AutoField, BooleanField, CharField, DateField, \
                             DateTimeField, FloatField, ForeignKey, Q, TextField, \
                             IntegerField, IPAddressField
from django.views.generic.simple import direct_to_template

import models as db

def str_modcls(obj):
    return '%s.%s' % (obj.__module__, obj.__class__)

def make_getter(field_name):
    """Creates a function which takes an instance of a model and retrieves
    the specified field.  Like Django, '__' may be used to access a field
    within a field."""
    fields = field_name.split('__', 1)
    if len(fields) == 1:
        return lambda o : o.__getattribute__(fields[0])
    else:
        f = make_getter(fields[1])
        return lambda o : f(o.__getattribute__(fields[0]))

class ModelSearchDescription():
    """Override this class and its field to specify which fields for a given
    model may be searched, grouped, and aggregated.  Only numeric fields may
    be aggregated.  Numeric fields may be properties instead of true fields on
    the model."""
    # the model this search description is for
    model = None

    # names of non-foreign key fields on the model to make group/searchable
    groupable_fields = ()
    searchable_fields = ()
    groupable_and_searchable_fields = ()

    # 2-tuples of foreign keys to make group/searchable.  First elt is the name
    # of the field and the second element is the associated SearchDescription.
    groupable_foreign_key_fields = ()
    searchable_foreign_key_fields = ()
    groupable_and_searchable_foreign_key_fields = ()

    # Should hold 2-tuples describing which fields may be aggregated.  The tuple
    # contains (verbose name, field name).  The verbose name is what will be
    # shown to the user while the field name may be a field or property.  Like
    # Django, '__' may be used to access a field within a field. (e.g., x__y).
    aggregatable_items = ()

class SearchDescription():
    """Describes what kind of searches can be done on a particular model and how
    those search results may be grouped.  This is essentially an efficient
    programatic representation of the user-friendly description provided by an
    instance of ModelSearchDescription."""
    # define what kinds of searches can be done on different kinds of fields
    SEARCH_OPERATORS_NUM  = ('exact', 'gt', 'gte', 'lt', 'lte', 'range')
    SEARCH_OPERATORS_TEXT = ('exact', 'contains', 'startswith', 'endswith', 'range')
    SEARCH_OPERATORS_DATE = ('exact', 'gt', 'gte', 'lt', 'lte', 'range', 'year', 'month', 'day')
    SEARCH_OPERATORS_BOOL = ('exact',)
    SEARCH_OPERATOR_TO_STR_MAPPING = dict(exact='=', gt='>', gte='>=', lt='<', lte='<=',
                             contains='contains', startswith='starts with', endswith='ends with',
                             year='is year', month='is month', day='is day')
    STR_TO_SEARCH_OPERATOR_MAPPING = dict([(v,k) for k,v in SEARCH_OPERATOR_TO_STR_MAPPING.iteritems()])

    GROUP_OPERATORS_NUM  = ('distinct values', 'fixed # of buckets', 'equi-width buckets', 'log-width buckets')
    GROUP_OPERATORS_TEXT = ('distinct values', 'first characters')
    GROUP_OPERATORS_DATE = ('distinct values', 'date', 'day of week', 'day of month', 'day of year', 'hour of day', 'month', 'year')
    GROUP_OPERATORS_BOOL = ('distinct values',)

    GROUP_OPERATORS_NEED_EXTRA_VALUE = ('first characters', 'fixed # of buckets', 'equi-width buckets', 'log-width buckets')

    @staticmethod
    def op_to_displayable_str(op):
        return SearchDescription.SEARCH_OPERATOR_TO_STR_MAPPING.get(op, op)

    def __init__(self, msd):
        """Takes a ModelSearchDescription and uses it to initialize this object."""
        self.model = msd.model

        # maps field name to a 2-tuple of (display name, search operators)
        self.searchable_fields = {}
        self.groupable_fields = {}
        for field in msd.groupable_fields:
            self.enable_grouping(field)
        for field in msd.searchable_fields:
            self.enable_searching(field)
        for field in msd.groupable_and_searchable_fields:
            self.enable_field(field)

        # maps field name to a 2-tuple of (display name, SearchDescription which
        # contains subfields which can be searched)
        self.searchable_foreign_key_fields = {}
        self.groupable_foreign_key_fields = {}
        for fk_field, sd in msd.groupable_foreign_key_fields:
            self.enable_foreign_key_grouping(fk_field, sd)
        for fk_field, sd in msd.searchable_foreign_key_fields:
            self.enable_foreign_key_searching(fk_field, sd)
        for fk_field, sd in msd.groupable_and_searchable_foreign_key_fields:
            self.enable_foreign_key_field(fk_field, sd)

        self.aggregatable_items = []
        for ai in msd.aggregatable_items:
            self.aggregatable_items.append(ai)

        # memoization vars
        self.group_up_to_date = False
        self.search_up_to_date = False
        self.processed_groupable_fields = None
        self.processed_groupable_fields_for_view = None
        self.processed_searchable_fields = None
        self.processed_searchable_fields_for_view = None

    def get_aggregatable_fields(self):
        return [fn for vn, fn in self.aggregatable_items]

    def get_aggregatable_fields_for_view(self):
        return [vn for vn, fn in self.aggregatable_items]

    def get_groupable_fields(self):
        """Returns all groupable fields on the associated model as a 3-tuple
        (field name, verbose field name, GROUP_OPERATORS_*) (names are fully
        qualified)."""
        if not self.group_up_to_date:
            self.__update_groupable_fields()
        return self.processed_groupable_fields

    def get_groupable_fields_for_view(self):
        """Returns all groupable fields on the associated model as a 2-tuple
        (verbose field name, operator) (names are fully qualified)."""
        if not self.group_up_to_date:
            self.__update_groupable_fields()
        return self.processed_groupable_fields_for_view

    def __update_groupable_fields(self):
        ret = [(n, v, o) for n, (v,o) in self.groupable_fields.items()]
        for field_name, (vname, model_search_desc) in self.groupable_foreign_key_fields.iteritems():
            for sub_field_name, sub_vname, sub_field_lookups in model_search_desc.get_groupable_fields():
                fqn = '__'.join((field_name, sub_field_name))
                fqvn = ' '.join((vname, sub_vname))
                ret.append( (fqn, fqvn, sub_field_lookups) )
        self.processed_groupable_fields = ret
        self.processed_groupable_fields_for_view = [(v, ops) for n,v,ops in ret]
        self.processed_groupable_fields_for_view.sort()
        self.group_up_to_date = True

    def get_searchable_fields(self):
        """Returns all searchable fields on the associated model as a 3-tuple
        (field name, verbose field name, SEARCH_OPERATORS_*) (names are fully
        qualified)."""
        if not self.search_up_to_date:
            self.__update_searchable_fields()
        return self.processed_searchable_fields

    def get_searchable_fields_for_view(self):
        """Returns all searchable fields on the associated model as a 2-tuple
        (verbose field name, operator in view form) (names are fully qualified)."""
        if not self.search_up_to_date:
            self.__update_searchable_fields()
        return self.processed_searchable_fields_for_view

    def __update_searchable_fields(self):
        ret = [(n, v, o) for n, (v,o) in self.searchable_fields.items()]
        for field_name, (vname, model_search_desc) in self.searchable_foreign_key_fields.iteritems():
            for sub_field_name, sub_vname, sub_field_lookups in model_search_desc.get_searchable_fields():
                fqn = '__'.join((field_name, sub_field_name))
                fqvn = ' '.join((vname, sub_vname))
                ret.append( (fqn, fqvn, sub_field_lookups) )
        self.processed_searchable_fields = ret
        self.processed_searchable_fields_for_view = [(v, [SearchDescription.op_to_displayable_str(o) for o in ops])
                                                        for n,v,ops in ret]
        self.processed_searchable_fields_for_view.sort()
        self.search_up_to_date = True

    def enable_grouping(self, field_name):
        """Enable grouping on the specified field name (may not be a foreign key field)."""
        self.enable_field(field_name, True, False)

    def enable_searching(self, field_name):
        """Enable search on the specified field name (may not be a foreign key field)."""
        self.enable_field(field_name, False, True)

    def enable_field(self, field_name, for_grouping=True, for_searching=True):
        """Enables the specified non-foreign-key field to be searched (if
        for_searching is True) and grouped by (if for_grouping is True)."""
        for field in self.model._meta.fields:
            if field.name == field_name:
                cls = field.__class__
                if cls in [AutoField, FloatField, IntegerField]:
                    gops = SearchDescription.GROUP_OPERATORS_NUM
                    sops = SearchDescription.SEARCH_OPERATORS_NUM
                elif cls in [CharField, IPAddressField, TextField]:
                    gops = SearchDescription.GROUP_OPERATORS_TEXT
                    sops = SearchDescription.SEARCH_OPERATORS_TEXT
                elif cls in [DateField, DateTimeField]:
                    gops = SearchDescription.GROUP_OPERATORS_DATE
                    sops = SearchDescription.SEARCH_OPERATORS_DATE
                elif cls in [BooleanField]:
                    gops = SearchDescription.GROUP_OPERATORS_BOOL
                    sops = SearchDescription.SEARCH_OPERATORS_BOOL
                elif cls == ForeignKey:
                    raise FieldError("May not enable search/grouping on foreign key fields with enable_field()")
                else:
                    raise FieldError("Don't know how to enable search/grouping for field of type %s.%s" % (cls.__module__, cls.__name__))

                # if verbose name is not a string, then just use the base name
                # as the verbose name
                verbose_name = field.verbose_name if type(field.verbose_name)==str else field.name

                if for_grouping:
                    self.group_up_to_date = False
                    self.groupable_fields[field.name] = (verbose_name, gops)
                if for_searching:
                    self.search_up_to_date = False
                    self.searchable_fields[field.name] = (verbose_name, sops)
                return
        raise FieldError('%s is not a field on %s' % (field_name, str_modcls(self.model)))

    def enable_foreign_key_grouping(self, field_name, foreign_search_desc):
        """Enable grouping on the specified field name which is a foreign key
        whose SearchDescription is passed as foreign_search_desc."""
        self.enable_foreign_key_field(field_name, foreign_search_desc, True, False)

    def enable_foreign_key_searching(self, field_name, foreign_search_desc):
        """Enable searching on the specified field name which is a foreign key
        whose SearchDescription is passed as foreign_search_desc."""
        self.enable_foreign_key_field(field_name, foreign_search_desc, False, True)

    def enable_foreign_key_field(self, field_name, foreign_search_desc, for_grouping=True, for_searching=True):
        """Enable searching (if for_searching) and grouping (if for_grouping) on
        the specified field name which is a foreign key whose SearchDescription
        is passed as foreign_search_desc."""
        for field in self.model._meta.fields:
            if field.name == field_name:
                if field.__class__ == ForeignKey:
                    m1 = foreign_search_desc.model
                    m2 = field.related.parent_model
                    if m1 == m2:
                        if for_grouping:
                            self.group_up_to_date = False
                            self.groupable_foreign_key_fields[field_name] = (field.verbose_name, foreign_search_desc)
                        if for_searching:
                            self.search_up_to_date = False
                            self.searchable_foreign_key_fields[field_name] = (field.verbose_name, foreign_search_desc)
                        return
                    else:
                        raise ValueError("The model supported by foreign_search_desc (%s) is not the model used by the specified foreign key field %s (%s)" % (str_modcls(m1), field_name, str_modcls(m2)))
                else:
                    raise FieldError('%s is not a ForeignKey field on %s' % (field_name, str_modcls(self.model)))
        raise FieldError('%s is not a field on %s' % (field_name, str_modcls(self.model)))

    def enable_aggregation(self, verbose_name, field_name):
        """Enable aggregation on the specified field.  The verbose name may be
        shown to the user."""
        self.aggregatable_items.append((verbose_name, field_name))

class Condition():
    """Stores information about a single condition.  Data is stored exactly as
    submitted from the HTML form.

    @param search_desc  The SearchDescription object this condition is for.
    """
    def __init__(self, search_desc,
                 field_index=None, op_index=None, field_value1=None, field_value2=None):
        self.searchable_views = search_desc.get_searchable_fields()
        self.searchable_views_ordered = search_desc.get_searchable_fields_for_view()
        self.field_index = field_index
        self.op_index = op_index
        self.field_value1 = field_value1
        self.field_value2 = field_value2

    def set(self, kind, value):
        """Sets the field specified by kind to the specified value.  ValueError
        is raised if kind is field or op and value is not an integer."""
        if kind == 'field':
            self.field_index = int(value)
        elif kind == 'op':
            self.op_index = int(value)
        elif kind == 'v1':
            self.field_value1 = value
        elif kind == 'v2':
            self.field_value2 = value
        else:
            raise KeyError("unknown kind '%s' passed to Condition.set()" % kind)

    def get_search_kv(self):
        """Gets the search field name (including operator, e.g., 'name__contains')
        and value as a 2-tuple.  IndexError is raised if an invalid search field
        or operator field choice was made.  It is also raised if any needed
        field is missing."""
        if not self.is_complete():
            raise IndexError('missing search field')

        try:
            field_name_long, ops = self.searchable_views_ordered[self.field_index]
        except IndexError:
            raise IndexError('invalid search field')

        field_name = None
        for n, v, _ in self.searchable_views:
            if field_name_long == v:
                field_name = n
                break
        if not field_name:
            raise KeyError('invalid search field')  # shouldn't be able to happen

        try:
            op = ops[self.op_index]
        except IndexError:
            raise IndexError('invalid operator selection')
        how = SearchDescription.STR_TO_SEARCH_OPERATOR_MAPPING[op]

        if op == 'range':
            if self.field_value2 is None:
                raise IndexError('missing search field for range operator')
            v = (self.field_value1, self.field_value2)
        else:
            v = self.field_value1

        k = '%s__%s' % (field_name, how)
        return (k, v)

    def is_complete(self):
        return self.field_index is not None  and \
               self.op_index is not None     and \
               self.field_value1 is not None

class Filter():
    """Represents a filter."""
    def __init__(self):
        self.conditions = {}

    def make_query_filter(self):
        """Creates a query for this filter.  IndexError is raised if an invalid
        search field or operator field choice is used by any condition."""
        dict_conditions = dict([c.get_search_kv() for c in self.conditions.values()])
        return Q(**dict_conditions)

    @staticmethod
    def combine_filters(filters):
        """OR all the filters together.  May raise IndexError (see make_query_filter)."""
        if not filters:
            return None
        overall_query = filters[0].make_query_filter()
        for f in filters[1:]:
            overall_query = overall_query | f.make_query_filter()
        return overall_query

class Group():
    """Stores information about a group.  Data is stored exactly as submitted by
    the HTML form.

    @param search_desc  The SearchDescription object this group is for.
    """
    def __init__(self, search_desc,
                 field_index=None, op_index=None, extra_value=None):
        self.groupable_views = search_desc.get_groupable_fields()
        self.groupable_views_ordered = search_desc.get_groupable_fields_for_view()
        self.field_index = field_index
        self.op_index = op_index
        self.extra_value = extra_value

        self.field_name_long = None
        self.field_name = None
        self.op = None
        self.align_to_0 = True

    def get_field_name_long(self):
        if self.field_name_long is None:
            self.prepare_for_use()
        return self.field_name_long

    def set(self, kind, value):
        """Sets the field specified by kind to the specified value.  ValueError
        is raised if value is not of the expected type (int for field and op, float o/w)."""
        if kind == 'field':
            self.field_index = int(value)
        elif kind == 'op':
            self.op_index = int(value)
        elif kind == 'v':
            self.extra_value = float(value)
        elif kind == 'opt':
            self.align_to_0 = (value == '0')
        else:
            raise KeyError("unknown kind '%s' passed to Group.set()" % kind)

    def prepare_for_use(self):
        """Prepares this object to be used for grouping.
        IndexError is raised if an invalid search field or operator field choice
        was made.  It is also raised if any needed field is missing."""
        if not self.is_complete():
            raise IndexError('missing group field')

        try:
            self.field_name_long, ops = self.groupable_views_ordered[self.field_index]
        except IndexError:
            raise IndexError('invalid group field')

        self.field_name = None
        for n, v, _ in self.groupable_views:
            if self.field_name_long == v:
                self.field_name = n
                break
        if not self.field_name:
            raise KeyError('invalid group field')  # shouldn't be able to happen

        try:
            self.op = ops[self.op_index]
        except IndexError:
            raise IndexError('invalid operator selection')

        if self.op in SearchDescription.GROUP_OPERATORS_NEED_EXTRA_VALUE:
            if self.extra_value is None:
                raise IndexError('missing group field extra value for operator which needs it')

    def is_complete(self):
        return self.field_index is not None and self.op_index is not None

    @staticmethod
    def __to_distinct_buckets(records, f_extract_bucket_key):
        buckets = {}
        for r in records:
            k = f_extract_bucket_key(r)
            try:
                buckets[k].append(r)
            except KeyError:
                buckets[k] = [r]
        keys = buckets.keys()
        keys.sort()
        return [(k, k, buckets[k]) for k in keys]

    def apply(self, records):
        """Returns a list of buckets.  Each bucket is a 3-tuple: (min value
        allowed (exclusive except for the first bucket), max value allowed
        (inclusive), list of items in the bucket).  If the min value and max
        value are the same then only items with that value will be in the bucket."""
        if self.field_name is None:
            self.prepare_for_use()

        # handle buckets which each only contains a distinct value
        f = None
        get_group_field_value = make_getter(self.field_name)
        if self.op == 'distinct values':
            f = lambda r : get_group_field_value(r)
        elif self.op == 'first characters':
            f = lambda r : get_group_field_value(r)[:int(self.extra_value)]
        elif self.op == 'date':
            f = lambda r : get_group_field_value(r).date()
        elif self.op == 'day of month':
            f = lambda r : get_group_field_value(r).day
        elif self.op == 'day of week':
            f = lambda r : get_group_field_value(r).weekday()
        elif self.op == 'day of year':
            f = lambda r : get_group_field_value(r).timetuple().tm_yday
        elif self.op == 'hour of day':
            f = lambda r : get_group_field_value(r).hour
        elif self.op == 'month':
            f = lambda r : get_group_field_value(r).month
        elif self.op == 'year':
            f = lambda r : get_group_field_value(r).year
        if f:
            return Group.__to_distinct_buckets(records, f)

        # handle buckets which contain a range of values
        sorted_kv_list = [(get_group_field_value(r), r) for r in records]
        sorted_kv_list.sort()
        min_value = sorted_kv_list[0][0]
        if min_value > 0 and self.align_to_0:
            min_value = 0.0
        max_value = sorted_kv_list[-1][0]
        range = float(max_value - min_value)
        if self.op == 'equi-width buckets':
            f_bucket_width = lambda i : self.extra_value
            #num_buckets = math.ceil(range / f_bucket_width())
        elif self.op == 'fixed # of buckets':
            num_buckets = int(self.extra_value)
            if self.extra_value < 1:
                raise ValueError('There must be at least one bucket.')
            f_bucket_width = lambda i : range / num_buckets
        elif self.op == 'log-width buckets':
            log_base = self.extra_value
            num_buckets = math.ceil(math.log(max_value, log_base))
            f_bucket_width = lambda i : math.pow(log_base, i)
        else:
            raise ValueError('internal error: unknown grouping operator')

        buckets = []
        bucket = []
        bucket_min = min_value
        bucket_width = f_bucket_width(0)
        bucket_max = bucket_min + bucket_width
        buckets.append((bucket_min, bucket_max, bucket))
        for k, v in sorted_kv_list:
            while k > bucket_max:
                bucket = []
                bucket_min = bucket_max
                bucket_width = f_bucket_width(len(buckets) - 1)
                bucket_max = bucket_min + bucket_width
                buckets.append((bucket_min, bucket_max, bucket))
            bucket.append(v)
        return buckets

def get_filtered_data(model, exclusive_filters, inclusive_filters):
    """Returns the QuerySet containing the data from the specified model which
    meets the criteria specified by any of the inclusive filters and none of the
    exclusive filters.  Raises IndexError if any of the filters conditions
    cannot be decoded."""
    exclusive_q = Filter.combine_filters(exclusive_filters)
    inclusive_q = Filter.combine_filters(inclusive_filters)
    if inclusive_q is None:
        if exclusive_q is None:
            return model.objects.all()
        else:
            return model.objects.exclude(exclusive_q)
    else:
        if exclusive_q is None:
            return model.objects.filter(inclusive_q)
        else:
            return model.objects.exclude(exclusive_q).filter(inclusive_q)

class GroupNode():
    def __init__(self, records, groupings, aggr_op, aggr_field, aggr_field_view_name, bmin=None, bmax=None):
        self.bmin = bmin
        self.bmax = bmax

        # if there are no more groupings, then just return the records
        if not groupings:
            self.records = records
            self.groups = None
            self.aggregated_value = self.__aggregate(aggr_op, aggr_field)
            self.field_on = aggr_field_view_name
        else:
            self.records = None
            groups_of_records = groupings[0].apply(records)
            self.field_on = groupings[0].get_field_name_long()
            subgroupings = groupings[1:]
            self.groups = [GroupNode(recs, subgroupings, aggr_op, aggr_field, aggr_field_view_name, bmin, bmax) for bmin, bmax, recs in groups_of_records]
            self.aggregated_value = None

        if self.bmin == self.bmax:
            self.range_str = str(self.bmin)
        else:
            self.range_str = '%s-%s' % (self.bmin, self.bmax)

    def __aggregate(self, how, field_name=None):
        """Aggregates the records in this group into a representative value
        Raises KeyError if an unknown operator is specified.  Raises AttributeError
        if the specified field cannot be accessed.

        @param how  the operator to use to combine the records (count,min,max,sum,average, or median)
        @param field_name  the field to apply the operator (not needed if how is count)
        """
        if not how:
            return None
        elif how == 'count':
            return len(self.records)

        get_group_field_value = make_getter(field_name)
        vals = (get_group_field_value(r) for r in self.records)
        if how == 'min':
            return min(vals)
        elif how == 'max':
            return max(vals)
        elif how == 'sum':
            return sum(vals)
        elif how == 'average':
            if len(self.records):
                return sum(vals) / float(len(self.records))
            else:
                return None # undefined
        elif how == 'median':
            vals_list = [v for v in vals]
            vals_list.sort()
            mid_index = len(vals_list) / 2
            if mid_index == len(vals_list)/2.0: # is the list even length?
                return (vals_list[mid_index] + vals_list[mid_index+1]) / 2.0
            else:
                return vals_list[mid_index]
        else:
            raise KeyError('unknown aggregation operator: %s' % how)

    def get_leftmost(self):
        if self.leaf():
            return self
        else:
            return self.groups[0]

    def get_aggregation_value(self):
        return self.aggregated_value

    def get_field_on(self):
        return self.field_on

    def is_leaf(self):
        return self.groups is None

    def get_groups(self):
        return self.groups

    def get_range_str(self):
        return self.range_str

    def get_records(self):
        return self.records

    def get_range_tuples(self, min_depth, max_depth, depth=0, prefix=()):
        """Gets every "range tuple" from min_depth (inclusive) to max_depth (exclusive)."""
        if depth >= min_depth+1:
            my_prefix = tuple(list(prefix) + [self.get_range_str()])
        else:
            my_prefix = ()

        if depth >= max_depth:
            return [my_prefix] if len(my_prefix)>0 else []
        else:
            ret = []
            if self.groups:
                for gn in self.groups:
                    ret.extend(gn.get_range_tuples(min_depth, max_depth, depth+1, my_prefix))
            return ret

    def yield_data(self, min_depth, max_depth, depth=0, prefix=()):
        """Yields a 3-tuple for every record contain (range tuple from min to
        max depth, range tuple for the remaining depths, aggregate value)."""
        if depth >= min_depth+1:
            my_prefix = tuple(list(prefix) + [self.get_range_str()])
        else:
            my_prefix = ()

        if depth >= max_depth:
            for gn in self.groups:
                for d in gn.__yield_data_only(my_prefix, ()):
                    yield d
        else:
            for gn in self.groups:
                for d in gn.yield_data(min_depth, max_depth, depth+1, my_prefix):
                    yield d

    def __yield_data_only(self, prefix1, prefix2):
        my_prefix = tuple(list(prefix2) + [self.get_range_str()])
        if self.is_leaf():
            yield (prefix1, my_prefix, self.get_aggregation_value())
        else:
            for gn in self.groups:
                for d in gn.__yield_data_only(prefix1, my_prefix):
                    yield d

def create_output_dump(group_node, indent_sz=0, group_num=-1, group_range=None):
    if group_node.is_leaf():
        txt_indent = ' ' * indent_sz
        recs = group_node.get_records()
        aggr_val = group_node.get_aggregation_value()
        aggr_txt = 'n/a' if aggr_val is None else '%.2f' % aggr_val
        if group_range is None:
            range_txt = ''
        else:
            bmin, bmax = group_range
            if bmin == bmax:
                range_txt = '(value=%s) ' % bmin
            else:
                range_txt = '(values %s to %s) ' % (bmin, bmax)
        ret = '' if group_num < 0 else '%sGroup %d %s(%d results) (aggr val=%s):\n' % (txt_indent, group_num, range_txt, len(recs), aggr_txt)
        return ret + txt_indent + ('\n%s' % txt_indent).join(str(r) for r in recs) + '\n'
    else:
        return '\n'.join(create_output_dump(sgn, indent_sz+2, i+1, (sgn.bmin,sgn.bmax)) for i, sgn in enumerate(group_node.get_groups()))

def create_table_output(group_fields_for_view, aggr_field_for_view, group_node, div_index):
    h = len(group_fields_for_view) + 1
    num_row_groups = div_index + 1       # 1 row per value in each row group
    num_col_groups = h - num_row_groups - 1  # 1 col per value in each col group

    num_hdr_rows = num_col_groups + 1
    num_hdr_cols = num_row_groups

    row_combos = list(set(group_node.get_range_tuples(0, num_row_groups)))
    row_combos.sort()
    col_combos = list(set(group_node.get_range_tuples(num_row_groups, h - 1)))
    col_combos.sort()
    txt = ''
    txt += '\nRCs: %s' % ' ;; '.join([str(t) for t in row_combos])
    txt += '\nCCs: %s' % ' ;; '.join([str(t) for t in col_combos])

    num_col_combos = len(col_combos)
    num_row_combos = len(row_combos)

    # build the first row
    fmt = '<th class="tbl_hdr_rowgrp"%s>%%s</th>' % ('' if num_hdr_rows == 1 else ' rowspan="%d"' % num_hdr_rows)
    hdr_row1_cols = '\n'.join(fmt % gfn for gfn in group_fields_for_view[:num_row_groups])
    hdr_row1_cols += '\n\t\t<th class="tbl_hdr_aggr" colspan="%d">%s</th>' % (num_col_combos, aggr_field_for_view)

    # build other header cells (for header rows at the top)
    header_cells = [[None]*num_col_combos for _ in range(num_col_groups)]
    col_map = {}  # maps a tuple of col groups to the column index it is in
    for i, cc in enumerate(col_combos):
        col_map[cc] = i + num_row_groups
        for j, v in enumerate(cc):
            header_cells[j][i] = v

    # create the actual header rows, merging cells which contain equivalent
    # values in adjacent columns
    cols_for_hdr_rows = [hdr_row1_cols]
    for row in header_cells:
        hdr_row = ''
        for i, v in enumerate(row):
            if v is not None:
                colspan = 1
                for j in xrange(i+1, num_col_combos):
                    if v == row[j]:
                        row[j] = None
                        colspan += 1
                    else:
                        break
                colspan_txt = '' if colspan==1 else ' colspan="%d"' % colspan
                hdr_row += '\n\t\t<th class="tbl_hdr_colgrp"%s>%s</th>' % (colspan_txt, v)
        cols_for_hdr_rows.append(hdr_row)
    hdr_rows = '\n'.join('\t<tr>\n\t\t%s\n\t</tr>' % cols for cols in cols_for_hdr_rows)

    # create a matrix to hold the rest of the table's data
    data_cells = [[None]*(num_row_groups+num_col_combos) for _ in range(num_row_combos)]

    # build other header cells (for header cols on the left)
    row_map = {}
    for i in xrange(num_row_combos):
        row_combo = row_combos[i]
        row_map[row_combo] = i
        for j in xrange(num_row_groups):
            data_cells[i][j] = row_combo[j]

    # collect each row of data (key = row range tuple)
    row_on = last_row = None
    debug_txt = ''
    for row_prefix, col_prefix, aggr_val in group_node.yield_data(0, num_row_groups):
        debug_txt += '<br/>  %s ;; %s ;;=> %s\n' % (row_prefix, col_prefix, aggr_val)
        col_on = col_map[col_prefix]
        if last_row != row_prefix:
            row_on = row_map[row_prefix] # usually row_on will be increasing sequentially, but only if records naturally appear in "order"
            last_row = row_prefix
        data_cells[row_on][col_on] = aggr_val

    # create the header cells text, merging where possible
    data_rows = ''
    for row_on, row in enumerate(data_cells):
        hdr_txt = ''
        for col_on in xrange(num_row_groups):
            v = row[col_on]
            if v is not None:
                rowspan = 1
                for r in xrange(row_on, len(data_cells)):
                    if data_cells[r][col_on] is None:
                        rowspan += 1
                    else:
                        break
                rowspan_txt = '' if rowspan==1 else ' rowspan="%d"' % rowspan
                hdr_txt += '<th%s>%s</th>' % (rowspan_txt, v)
            else:
                pass # merged into another cell
        data_rows += '\n\t<tr>' + hdr_txt + ''.join('<td>%s</td>' % ('&nbsp;' if c is None else c) for c in row[num_row_groups:]) + '</tr>'

    return '<table class="tbl_results" border="1px">\n' + hdr_rows + '\n' + data_rows + '\n</table>' + '\n\n' + txt + '\n\n' + debug_txt

class TemplateSearchDesc(ModelSearchDescription):
    model = db.TopologyTemplate
    groupable_and_searchable_fields = ('name',)
SD_TEMPLATE = SearchDescription(TemplateSearchDesc)

class UserSearchDesc(ModelSearchDescription):
    model = User
    groupable_and_searchable_fields = ('username',)
SD_USER = SearchDescription(UserSearchDesc)

class OrganizationSearchDesc(ModelSearchDescription):
    model = db.Organization
    groupable_and_searchable_fields = ('name', )
SD_ORG = SearchDescription(OrganizationSearchDesc)

class UserProfileSearchDesc(ModelSearchDescription):
    model = db.UserProfile
    groupable_and_searchable_fields = ('pos', 'retired')
    groupable_and_searchable_foreign_key_fields = ( ('user', SD_USER), ('org', SD_ORG) )
SD_USERPROFILE = SearchDescription(UserProfileSearchDesc)

class UsageStatsSearchDesc(ModelSearchDescription):
    model = db.UsageStats
    groupable_and_searchable_fields = ('topo_uuid', 'time_connected', 'num_pkts_to_topo')
    groupable_and_searchable_foreign_key_fields = ( ('template',SD_TEMPLATE), ('userprof', SD_USERPROFILE) )
    aggregatable_items = (('Total Time Connected', 'total_time_connected_sec'),
                          ('Total Bytes Transferred', 'total_bytes'),
                          ('Total Packets Transferred', 'total_packets'))
SD_USAGE_STATS = SearchDescription(UsageStatsSearchDesc)

def create_stats_search_page(request):
    d = {'gfields_list': SD_USAGE_STATS.get_groupable_fields_for_view(),
         'sfields_list': SD_USAGE_STATS.get_searchable_fields_for_view(),
         'afields_list': SD_USAGE_STATS.get_aggregatable_fields_for_view()}
    return direct_to_template(request, 'vns/stats_search.html', d)

RE_MODEL_SEARCH_FIELD = re.compile(r'(e|i)(\w+)_(\d+)_((field)|(op)|(v1)|(v2))')
RE_MODEL_GROUP_FIELD  = re.compile(r'group(\w+)_((field)|(opt)|(v)|(op))')
def stats_search(request):
    # make sure the user is logged in
    if not request.user.is_authenticated():
        messages.warning(request, 'You must login before proceeding.')
        return HttpResponseRedirect('/login/?next=%s' % request.path)

    if request.method == 'POST':
        # extract all of the inclusive and exclusive filters
        in_filters = {}
        ex_filters = {}
        groups = {}
        for k,v in request.POST.iteritems():
            m = RE_MODEL_SEARCH_FIELD.match(k)
            if m:
                f_type, f_id, c_id, kind, _,_,_,_ = m.groups()
                filters = in_filters if f_type=='i' else ex_filters
                try:
                    f = filters[f_id]
                except KeyError:
                    f = Filter()
                    filters[f_id] = f
                try:
                    c = f.conditions[c_id]
                except KeyError:
                    c = Condition(SD_USAGE_STATS)
                    f.conditions[c_id] = c
                try:
                    c.set(kind, v)
                except ValueError:
                    # user has supplied a non-integer field or op index: they didn't use our form
                    messages.error(request, 'Invalid search: please use our search form')
                    return create_stats_search_page(request)
                continue

            m = RE_MODEL_GROUP_FIELD.match(k)
            if m:
                g_id, kind, _,_,_,_ = m.groups()
                try:
                    g = groups[g_id]
                except KeyError:
                    g = Group(SD_USAGE_STATS)
                    groups[g_id] = g
                try:
                    if kind != 'v' or v != '':
                        g.set(kind, v)
                except ValueError as e:
                    if kind == 'v':
                        messages.error(request, 'Invalid value supplied: %s' % str(e))
                    else:
                        # user has supplied a non-integer field or op index: they didn't use our form
                        messages.error(request, 'Invalid group: please use our search form')
                        return create_stats_search_page(request)
                continue

        try:
            aggr_op = request.POST['aggr_op']
            aggr_field_index = int(request.POST['aggr_field'])
            aggr_field = SD_USAGE_STATS.get_aggregatable_fields()[aggr_field_index]
            if aggr_op == 'count':
                aggr_field_for_view = 'Count'
            else:
                aggr_field_for_view = SD_USAGE_STATS.get_aggregatable_fields_for_view()[aggr_field_index]
        except (KeyError, IndexError, ValueError):
            messages.error(request, 'Missing or invalid aggregation operator info: please use our search form')
            return create_stats_search_page(request)

        try:
            data = get_filtered_data(db.UsageStats, ex_filters.values(), in_filters.values())
        except IndexError as e:
            # user has supplied a bad field or operator: they didn't use our form
            messages.error(request, 'Invalid search: ' + str(e))
            return create_stats_search_page(request)

        # put the groupings in order and prepare them for use
        group_ids = groups.keys()
        group_ids.sort()
        groups = [groups[g_id] for g_id in group_ids]
        group_field_names_long = [g.get_field_name_long() for g in groups]
        try:
            grouped_data = GroupNode(data, groups, aggr_op, aggr_field, aggr_field_for_view)
        except IndexError as e:
            # user has supplied a bad field or operator: they didn't use our form
            messages.error(request, 'Invalid grouping: ' + str(e))
            return create_stats_search_page(request)
        except (KeyError, AttributeError):
            messages.error(request, 'Invalid aggregation operator or field')
            return create_stats_search_page(request)

        # determine the group divider indices
        try:
            chart_div_gindex = int(request.POST.get('chart_div_gindex', 0));
            if chart_div_gindex < 0 or chart_div_gindex > len(groups):
                raise ValueError

            table_div_gindex = int(request.POST.get('table_div_gindex', 0));
            if table_div_gindex < -1 or table_div_gindex > len(groups):
                raise ValueError
        except (KeyError, ValueError):
            messages.error(request, 'Invalid divider value: please use our search form')
            return create_stats_search_page(request)

        if len(group_ids) == 0:
            # no groups => aggregates into just a single value
            val = grouped_data.get_aggregation_value()
            output = '%s = %s' % (aggr_field_for_view, val)
            return HttpResponse(output, content_type='text/plain')

        output = create_output(grouped_data)
        #return HttpResponse(output, content_type='text/plain')

        table_output = create_table_output(group_field_names_long, aggr_field_for_view, grouped_data, table_div_gindex)
        return HttpResponse(table_output, content_type='text/html')
    else:
        return create_stats_search_page(request)
