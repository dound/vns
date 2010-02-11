from django.core.exceptions import FieldError
from django.db.models import AutoField, BooleanField, CharField, DateField, \
                             DateTimeField, FloatField, ForeignKey, TextField, \
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

    # names of non-foreign key fields on the model to make searchable
    fields = ()

    # 2-tuples of foreign key fields make searchable.  First element is the name
    # of the field and the second element is the associated SearchDescription.
    foreign_key_fields = ()

class SearchDescription():
    # define what kinds of searches can be done on different kinds of fields
    SEARCH_OPERATORS_NUM  = ('exact', 'gt', 'gte', 'lt', 'lte', 'range')
    SEARCH_OPERATORS_TEXT = ('exact', 'contains', 'startswith', 'endswith', 'range')
    SEARCH_OPERATORS_DATE = ('exact', 'gt', 'gte', 'lt', 'lte', 'range', 'year', 'month', 'day')
    SEARCH_OPERATORS_BOOL = ('exact',)

    OP_TO_STR_MAPPING = dict(exact='=', gt='>', gte='>=', lt='<', lte='<=',
                             startswith='starts with', endswith='ends with',
                             year='is year', month='is month', day='is day')
    @staticmethod
    def op_to_displayable_str(op):
        return SearchDescription.OP_TO_STR_MAPPING.get(op, op)

    def __init__(self, msd):
        """Takes a ModelSearchDescription and uses it to initialize this object."""
        self.model = msd.model

        # maps field name to a 2-tuple of (display name, search operators)
        self.searchable_fields = {}
        for field in msd.fields:
            self.enable_search(field)

        # maps field name to a 2-tuple of (display name, SearchDescription which
        # contains subfields which can be searched)
        self.searchable_foreign_key_fields = {}
        for fk_field, sd in msd.foreign_key_fields:
            self.enable_foreign_key_search(fk_field, sd)

    def get_searchable_fields(self):
        """Returns all searchable fields on the associated model as a 3-tuple
        (field name, verbose field name, SEARCH_OPERATORS_*) (names are fully
        qualified)."""
        ret = [(n, v, o) for n, (v,o) in self.searchable_fields.items()]
        for field_name, (vname, model_search_desc) in self.searchable_foreign_key_fields.iteritems():
            for sub_field_name, sub_vname, sub_field_lookups in model_search_desc.get_searchable_fields():
                fqn = '.'.join((field_name, sub_field_name))
                fqvn = ' '.join((vname, sub_vname))
                ret.append( (fqn, fqvn, sub_field_lookups) )
        return ret

    def enable_search(self, field_name):
        """Enable search on the specified field name (may not be a foreign key field)."""
        for field in self.model._meta.fields:
            if field.name == field_name:
                cls = field.__class__
                if cls in [AutoField, FloatField, IntegerField]:
                    ops = SearchDescription.SEARCH_OPERATORS_NUM
                elif cls in [CharField, IPAddressField, TextField]:
                    ops = SearchDescription.SEARCH_OPERATORS_TEXT
                elif cls in [DateField, DateTimeField]:
                    ops = SearchDescription.SEARCH_OPERATORS_DATE
                elif cls in [BooleanField]:
                    ops = SearchDescription.SEARCH_OPERATORS_BOOL
                elif cls == ForeignKey:
                    raise FieldError("May not enable search on foreign key fields with enable_search()")
                else:
                    raise FieldError("Don't know how to enable search for field of type %s.%s" % (cls.__module__, cls.__name__))
                self.searchable_fields[field.name] = (field.verbose_name, ops)
                return
        raise FieldError('%s is not a field on %s' % (field_name, str_modcls(self.model)))

    def enable_foreign_key_search(self, field_name, foreign_search_desc):
        """Enable search on the specified field name which is a foreign key
        whose SearchDescription is passed as foreign_search_desc."""
        for field in self.model._meta.fields:
            if field.name == field_name:
                if field.__class__ == ForeignKey:
                    m1 = foreign_search_desc.model
                    m2 = field.related.parent_model
                    if m1 == m2:
                        self.searchable_foreign_key_fields[field_name] = (field.verbose_name, foreign_search_desc)
                        return
                    else:
                        raise ValueError("The model supported by foreign_search_desc (%s) is not the model used by the specified foreign key field %s (%s)" % (str_modcls(m1), field_name, str_modcls(m2)))
                else:
                    raise FieldError('%s is not a ForeignKey field on %s' % (field_name, str_modcls(self.model)))
        raise FieldError('%s is not a field on %s' % (field_name, str_modcls(self.model)))

class TemplateSearchDesc(SearchDescription):
    model = db.TopologyTemplate
    fields = ('name',)
    foreign_key_fields = ()
SD_TEMPLATE = SearchDescription(TemplateSearchDesc)

class UsageStatsSearchDesc(SearchDescription):
    model = db.UsageStats
    fields = ('topo_uuid', 'time_connected', 'num_pkts_to_topo')
    foreign_key_fields = ( ('template',SD_TEMPLATE), )
SD_TOPOLOGY = SearchDescription(UsageStatsSearchDesc)

# precompute them and store them in sorted order
TOPOLOGY_SEARCHABLE_FIELDS = SD_TOPOLOGY.get_searchable_fields()
TOPOLOGY_SEARCHABLE_FIELDS_FOR_VIEW = [(v, [SearchDescription.op_to_displayable_str(o) for o in ops])
                                       for n,v,ops in TOPOLOGY_SEARCHABLE_FIELDS]
TOPOLOGY_SEARCHABLE_FIELDS_FOR_VIEW.sort()
TOPOLOGY_SEARCHABLE_FIELDS_FOR_DECODE = [(v, n) for n,v,ops in TOPOLOGY_SEARCHABLE_FIELDS]
