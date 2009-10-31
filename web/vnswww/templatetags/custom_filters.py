from django import template
register = template.Library()

@register.filter(name='durationf')
def durationf(num_secs):
    """Returns a string represented the time this topology has been connected."""
    if num_secs > 3600:
        return '%.1fhr' % (num_secs / 3600.0)
    elif num_secs > 60:
        return '%.1fmin' % (num_secs / 60.0)
    else:
        return '%dsec' % num_secs

@register.filter(name='durationf_ifnonzero')
def durationf_ifnonzero(num_secs, format='%s'):
    """Format format with a single string representing num_secs as a
    human-readable time formatted by durationf.  If num_secs secs is zero, the
    empty string is returned."""
    if num_secs == 0:
        return ''
    else:
        return format % durationf(num_secs)
