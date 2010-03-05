import re

from django.contrib import messages
from django.core.exceptions import FieldError
from django.http import HttpResponse, HttpResponseRedirect
from django.db.models import AutoField, BooleanField, CharField, DateField, \
                             DateTimeField, FloatField, ForeignKey, Q, TextField, \
                             IntegerField, IPAddressField
from django.views.generic.simple import direct_to_template

import models as db

def str_modcls(obj):
    return '%s.%s' % (obj.__module__, obj.__class__)

class ModelSearchDescription():
    """Override this class and the model, fields, and foreign_key_fields values
    and then this object can be used to initialize SearchDescription."""
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

    GROUP_OPERATORS_NUM  = ('distinct', 'fixed # of buckets', 'equi-width buckets', 'log-width buckets')
    GROUP_OPERATORS_TEXT = ('distinct', 'first characters')
    GROUP_OPERATORS_DATE = ('distinct', 'day of week', 'day of month', 'day of year', 'hour of day', 'day', 'month', 'year')
    GROUP_OPERATORS_BOOL = ('distinct',)

    @staticmethod
    def op_to_displayable_str(op):
        return SearchDescription.SEARCH_OPERATOR_TO_STR_MAPPING.get(op, op)

    def __init__(self, msd):
        """Takes a ModelSearchDescription and uses it to initialize this object."""
        self.model = msd.model

        # maps field name to a 2-tuple of (display name, search operators)
        self.searchable_fields = {}
        self.groupable_fields = {}
        for field in msd.__dict__.get('groupable_fields', []):
            self.enable_grouping(field)
        for field in msd.__dict__.get('searchable_fields', []):
            self.enable_searching(field)
        for field in msd.__dict__.get('groupable_and_searchable_fields', []):
            self.enable_field(field)

        # maps field name to a 2-tuple of (display name, SearchDescription which
        # contains subfields which can be searched)
        self.searchable_foreign_key_fields = {}
        self.groupable_foreign_key_fields = {}
        for fk_field, sd in msd.__dict__.get('groupable_foreign_key_fields', []):
            self.enable_foreign_key_grouping(fk_field, sd)
        for fk_field, sd in msd.__dict__.get('searchable_foreign_key_fields', []):
            self.enable_foreign_key_searching(fk_field, sd)
        for fk_field, sd in msd.__dict__.get('groupable_and_searchable_foreign_key_fields', []):
            self.enable_foreign_key_field(fk_field, sd)

        # memoization vars
        self.group_up_to_date = False
        self.search_up_to_date = False
        self.processed_groupable_fields = None
        self.processed_groupable_fields_for_view = None
        self.processed_searchable_fields = None
        self.processed_searchable_fields_for_view = None

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

                if for_grouping:
                    self.group_up_to_date = False
                    self.groupable_fields[field.name] = (field.verbose_name, gops)
                if for_searching:
                    self.search_up_to_date = False
                    self.searchable_fields[field.name] = (field.verbose_name, sops)
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

def create_output(groups):
    return '%d results\n\n' % len(groups) + '\n'.join(str(g) for g in groups)

class TemplateSearchDesc(SearchDescription):
    model = db.TopologyTemplate
    groupable_and_searchable_fields = ('name',)
    groupable_and_searchable_foreign_key_fields = ()
SD_TEMPLATE = SearchDescription(TemplateSearchDesc)

class UsageStatsSearchDesc(SearchDescription):
    model = db.UsageStats
    groupable_and_searchable_fields = ('topo_uuid', 'time_connected', 'num_pkts_to_topo')
    groupable_and_searchable_foreign_key_fields = ( ('template',SD_TEMPLATE), )
SD_USAGE_STATS = SearchDescription(UsageStatsSearchDesc)

def create_stats_search_page(request):
    d = {'gfields_list': SD_USAGE_STATS.get_groupable_fields_for_view(),
         'sfields_list': SD_USAGE_STATS.get_searchable_fields_for_view()}
    return direct_to_template(request, 'vns/stats_search.html', d)

RE_MODEL_SEARCH_FIELD = re.compile(r'(e|i)(\w+)_(\d+)_((field)|(op)|(v1)|(v2))')
def stats_search(request):
    # make sure the user is logged in
    if not request.user.is_authenticated():
        messages.warning(request, 'You must login before proceeding.')
        return HttpResponseRedirect('/login/?next=%s' % request.path)


    if request.method == 'POST':
        # extract all of the inclusive and exclusive filters
        in_filters = {}
        ex_filters = {}
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
                    messages.error('Invalid search: please use our search form')
                    return create_stats_search_page(request)

        try:
            data = get_filtered_data(db.UsageStats, ex_filters.values(), in_filters.values())
        except IndexError as e:
            # user has supplied a bad field or operator: they didn't use our form
            messages.error('Invalid search: ' + str(e))
            return create_stats_search_page(request)

        output = create_output(data)
        return HttpResponse(output, content_type='text/plain')
    else:
        return create_stats_search_page(request)
