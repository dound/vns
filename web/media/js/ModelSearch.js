/**
 * This function creates dynamic form elements for searching a model.  The input
 * fields it creates will be of the form "<prefix><type><filter#>_<condition#>_<field>"
 * where <type> is either "i" or "e" (inclusive/exclusive filter) and <field>
 * is "field" (index of the field this filter's condition is on), "op" (index of
 * the operator to search the field with), or "v1" or "v2" (search values; v2
 * may only be applicable for some operators).  The field and operator index
 * correspond to the position of elements in the field_infos argument.
 *
 * It also creates similar form elements for specifying how to group results.
 * The input fields for grouping will be of the form "<prefix>group<group#>_<field>"
 * where <field> is "field", "op", or "v" (specifies a value associated with op,
 * if needed, e.g., bucket width).
 *
 * Form elements are also posted which indicate how to aggregate each group and
 * on what field to do aggregation.  <prefix>aggr_op specifies how and is one of
 * AGGR_OPS_* and <prefix>aggr_field specifies what field the operator is
 * performed on (if applicable).
 *
 * URL parameters can be used to initialize the filters.  To have filters
 * automatically created pass the following parameters:
 *     <prefix><type>_num_filters - number of filters to create
 *     <prefix><type><filter#>_num_conds - number of conditions for the specified filter
 *     <prefix><type><filter#>_<cond#>_<field> - specifies a condition for the specified filter
 *     note: filters and conditions must be numbered from 1 to n.
 *
 * Group form fields can likewise be initialized from URL parameters:
 *     <prefix>num_groups
 *     <prefix>group<group#>_<field>
 *
 * Aggregate form fields can also be initialized from URL paramters:
 *     <prefix>aggr_field
 *     <prefix>aggr_op
 *
 * @param prefix       Text to prefix each input field with
 * @param gfield_infos An of information about groupable fields.  Same structure
 *                     as sfield_infos.
 * @param sfield_infos An array of information about searchable fields.  Each
 *                     element is an array of two items: the name of the field
 *                     and an array of operators it can use.
 * @param afield_infos An array of fields which may be aggregated on.
 * @param inclusive_node  DOM element where inclusive form fields should be put
 * @param exclusive_node  DOM element where exclusive form fields should be put
 * @param groups_node     DOM element where grouping form fields should be put.
 *
 * @author David Underhill (http://www.dound.com)
 */
function createModelSearch(prefix, gfield_infos, sfield_infos, afield_infos, inclusive_node, exclusive_node, groups_node) {
    // constants
    var S_OP_NEEDS_TWO_VALUES = ['range'];
    var G_OP_NEEDS_EXTRA_VALUE = ['first characters', 'fixed # of buckets', 'equi-width buckets', 'log-width buckets'];
    var G_OP_NEEDS_EXTRA_VALUE_DESC = ['# of chars', '# of buckets', 'bucket width', 'log base'];
    var G_OP_HAS_ALIGN_TO_0_OPT = ['fixed # of buckets', 'equi-width buckets', 'log-width buckets'];
    var G_ALIGN_TO_0_OPT_OPTIONS = "<option value='0'>Start At 0</option><option value='min'>Start At Min</option>";
    var AGGR_OPS_NULLARY = ['count'];
    var AGGR_OPS_UNARY = ['average', 'max', 'median', 'min', 'sum'];

    // build option element html for field options and fields' operator options
    var G_FIELD_OPTIONS, G_OPERATORS_OPTIONS, S_FIELD_OPTIONS, S_OPERATORS_OPTIONS, A_FIELD_OPTIONS, A_OPERATORS_OPTIONS;
    function create_options(infos, has_options) {
        var i, j, field_info, field_name, field_ops, field_options, op_name, op_options, options;
        field_options = '';
        op_options = [];
        for(i=0; i<infos.length; i++) {
            field_info = infos[i];
            field_name = field_info[0];
            field_options += "<option value='" + i + "'>" + field_name + "</option>";

            if(has_options === true) {
                field_ops = field_info[1];
                options = '';
                for(j=0; j<field_ops.length; j++) {
                    op_name = field_ops[j];
                    options += "<option value ='" + j + "'>" + op_name + "</option";
                }
                op_options[i] = options;
            }
        }
        return [field_options, op_options];
    }
    (function () {
        var pair;
        pair = create_options(gfield_infos, true);
        G_FIELD_OPTIONS = pair[0];
        G_OPERATORS_OPTIONS = pair[1];
        pair = create_options(sfield_infos, true);
        S_FIELD_OPTIONS = pair[0];
        S_OPERATORS_OPTIONS = pair[1];
        pair = create_options(afield_infos, false);
        A_FIELD_OPTIONS = pair[0];
    }());
    (function () {
        var i, options, op;
        options = '';
        for(i=0; i<AGGR_OPS_NULLARY.length; i++) {
            op = AGGR_OPS_NULLARY[i];
            options += "<option value='" + op + "'>" + op + "</option>";
        }
        for(i=0; i<AGGR_OPS_UNARY.length; i++) {
            op = AGGR_OPS_UNARY[i];
            options += "<option value='" + op + "'>" + op + "</option>";
        }
        A_OPERATORS_OPTIONS = options;
    }());

    /** create a textual input field */
    function createValueField(cname, id) {
        var v = document.createElement('input');
        v.setAttribute('name', cname + '_v' + id);
        v.setAttribute('type', 'text');
        return v;
    }

    /** create a button which does not submit the form */
    function createOrdinaryButton(caption) {
        var btn = document.createElement('button');
        btn.innerHTML = caption;
        btn.setAttribute('type', 'button');
        return btn;
    }

    /** parses the URL and returns the value of the parameter with the specified name, if any */
    function get_url_param(name) {
        var url, results;
        url = window.location.href;
        name = name.replace(/[\[]/,"\\\[").replace(/[\]]/,"\\\]");
        results = new RegExp("[\\?&]"+name+"=([^&#]*)").exec(url);
        if(results === null) {
            return null;
        }
        else { // decodeURIComponent doesn't recognize + as encoding for space
            return decodeURIComponent(results[1].replace(/\+/g," "));
        }
    }

    /**
     * A Condition manages what restrictions are on a single field.
     *
     * @param parent_fitler  filter which this condition is part of
     * @param cname          unique name of this condition
     * @param container      DOM element which will hold this condition's elements
     * @param n              this condition's number
     */
    function Condition(parent_filter, cname, container, n) {
        var me, field_choices, op_choices, value1, txtBetweenValues, value2, btnRm;
        me = this;
        this.parent_filter = parent_filter;
        this.container = container;

        this.leading_span = document.createElement('span');
        this.leading_span.appendChild(document.createTextNode(' AND '));
        container.appendChild(this.leading_span);
        this.renumber(n);

        field_choices = document.createElement('select');
        op_choices = document.createElement('select');
        value1 = createValueField(cname, 1);
        txtBetweenValues = document.createTextNode(' to ');
        value2 = createValueField(cname, 2);

        this.field_choices = field_choices;
        this.op_choices = op_choices;
        this.value1 = value1;
        this.value2 = value2;

        // initialize the field choices combo box
        field_choices.setAttribute('name', cname + '_field');
        field_choices.innerHTML = S_FIELD_OPTIONS;
        field_choices.onchange = function () {
            // show the operators allowed with this kind of field
            op_choices.innerHTML = S_OPERATORS_OPTIONS[field_choices.selectedIndex];
            op_choices.onchange();
        };

        //initialize the operator choices combo box
        op_choices.setAttribute('name', cname + '_op');
        op_choices.onchange = function () {
            // show the number of value fields as appropriate
            var i, op, state;
            op = op_choices.options[op_choices.selectedIndex].innerHTML;
            state = 'none';
            for(i=0; i<S_OP_NEEDS_TWO_VALUES.length; i++) {
                if(op === S_OP_NEEDS_TWO_VALUES[i]) {
                    state = 'inline';
                    break;
                }
            }
            txtBetweenValues.nodeValue = (state === 'inline') ? ' to ' : '';
            value2.style.display = state;
        };

        // create a button to delete this condition
        btnRm = createOrdinaryButton('X');
        btnRm.onclick = function() { me.remove(); };

        // add each of the new elements to our container
        container.appendChild(field_choices);
        container.appendChild(op_choices);
        container.appendChild(value1);
        container.appendChild(txtBetweenValues);
        container.appendChild(value2);
        container.appendChild(btnRm);

        // trigger onchange() for the default selections
        field_choices.onchange();
    }

    /** deletes this condition (removes it from the DOM and from its Filter) */
    Condition.prototype.remove = function () {
        this.container.parentNode.removeChild(this.container);
        this.parent_filter.condition_deleted_callback(this);
    };

    /** Changes the number of this condition (1 is first). */
    Condition.prototype.renumber = function (n) {
        this.leading_span.style.visibility = ((n === 1) ? 'hidden' : 'visible');
    };

    /** Sets the condition */
    Condition.prototype.set = function (field, op, v1, v2) {
        this.field_choices.selectedIndex = field;
        this.field_choices.onchange();
        this.op_choices.selectedIndex = op;
        this.op_choices.onchange();
        this.value1.value = v1;
        this.value2.value = v2;
    };

    /**
     * A Filter manages a set of conditions.
     *
     * @param parent_fs  FilterSet which is the parent of this Filter
     * @param fname      unique name of this filter
     * @param container  DOM element which will hold this filter's elements
     * @param n          which filter number this is (1 indexed)
     */
    function Filter(parent_fs, fname, container, n) {
        var me = this;
        this.parent_fs = parent_fs;
        this.fname = fname;
        this.container = container;

        // conditions associated with this filter (these are AND'ed together)
        this.conditions = [];

        // id to use for the next condition
        this.next_cond_id = 0;

        // create the default contents of the container node for this filter
        this.txtJoin = document.createTextNode('');
        container.appendChild(this.txtJoin);
        this.renumber(n);
        this.conditions_container = document.createElement('blockquote');
        container.appendChild(this.conditions_container);

        // create a button to add more conditions
        this.btnAddCondition = createOrdinaryButton('AND ...');
        this.conditions_container.appendChild(this.btnAddCondition);

        // create the default condition
        this.add_condition();

        // clicking on the button should create a new condition
        this.btnAddCondition.onclick = function () { me.add_condition(); };
    }

    /** adds a new condition to a filter */
    Filter.prototype.add_condition = function () {
        var cname, cdiv;

        // add a new condition to this filter
        cname = this.fname + '_' + this.next_cond_id;
        this.next_cond_id = this.next_cond_id + 1;
        cdiv = document.createElement('div');
        this.conditions.push(new Condition(this, cname, cdiv, this.conditions.length+1));
        this.conditions_container.insertBefore(cdiv, this.btnAddCondition);
        return this.conditions[this.conditions.length - 1];
    };

    /** callback issued when a condition is deleted from a filter */
    Filter.prototype.condition_deleted_callback = function (c) {
        var i;

        // if the last condition is being removed, then delete this filter
        if(this.conditions.length === 1) {
            this.container.parentNode.removeChild(this.container);
            this.parent_fs.filter_deleted_callback(this);
        }
        else {
            // remove c from our list of conditions
            for(i=0; i<this.conditions.length; i++) {
                if(this.conditions[i] === c) {
                    this.conditions.splice(i, 1);
                    break;
                }
            }

            // renumber remaining conditions
            for(; i<this.conditions.length; i++) {
                this.conditions[i].renumber(i+1);
           }
        }
    };

    /** renumber this filter */
    Filter.prototype.renumber = function (n) {
        this.txtJoin.nodeValue = ((n === 1) ? '' : 'OR ') + 'Filter #' + n;
    };

    /**
     * A FilterSet manages a set of filters and their conditions.
     *
     * @param inclusive  boolean which says whether this is the in/exclusive set
     * @param container  DOM node element to populate with the filters
     */
    function FilterSet(inclusive, container) {
        var me = this; // need a func to refer back to this object, not a button

        // prefix associated with this filter set for form fields
        this.FORM_PREFIX = prefix + (inclusive ? 'i' : 'e');

        this.container = container;

        // filters associated with this set (these are OR'ed together)
        this.filters = [];

        // id to use for the next filter
        this.next_filter_id = 0;

        // initial contents
        this.default_contents = document.createElement('div');
        if(inclusive) {
            this.default_contents.innerHTML = 'No filters specified: all records will be included.';
        }
        else {
            this.default_contents.innerHTML = 'No filters specified: no records will be filtered out from the inclusive filter results.';
        }
        this.container.appendChild(this.default_contents);

        // create the default contents of the filter set's container node
        this.btnAddFilter = createOrdinaryButton('Add a filter');
        this.btnAddFilter.onclick = function () { me.add_filter(); };
        this.container.appendChild(this.btnAddFilter);

        // populate them with any params passed in the URL
        this.populate_from_url();
    }

    /** Add a filter to the filter set. */
    FilterSet.prototype.add_filter = function (fname) {
        var fdiv;
        if(fname === undefined) {
            fname = this.FORM_PREFIX + this.next_filter_id;
        }
        fdiv = document.createElement('div');
        this.filters.push(new Filter(this, fname, fdiv, this.filters.length+1));
        this.next_filter_id += 1;
        this.container.insertBefore(fdiv, this.btnAddFilter);

        // hide the default contents
        this.default_contents.style.display = 'none';
        this.btnAddFilter.innerHTML = 'Add another filter';
        return this.filters[this.filters.length - 1];
    };

    /** Callback to issue when a filter from this set is deleted. */
    FilterSet.prototype.filter_deleted_callback = function (f) {
        var i;
        // remove f from filters
        for(i=0; i<this.filters.length; i++) {
            if(this.filters[i] === f) {
                this.filters.splice(i, 1);
                break;
            }
        }

        // renumber the remaining filters
        for(; i<this.filters.length; i++) {
            this.filters[i].renumber(i+1);
        }

        // show the default contents again if there are no filters left
        if(this.filters.length === 0) {
            this.default_contents.style.display = 'block';
            this.btnAddFilter.innerHTML = 'Add a filter';
        }
    };

    /** Parses URL parameters and creates filters for this filter set. */
    FilterSet.prototype.populate_from_url = function() {
        var cond, cprefix, filter, fname, fprefix, i, j, num_conds, num_filters, field, op, v1, v2;

        num_filters = get_url_param(this.FORM_PREFIX + "_num_filters");
        if(num_filters === null) {
            return; // no filters
        }

        for(i=1; i<=num_filters; i++) {
            fname = this.FORM_PREFIX + i;
            fprefix = fname + '_';
            num_conds = get_url_param(fprefix + "num_conds");
            if(num_conds !== null && num_conds > 0) {
                filter = this.add_filter(fname);
                for(j=1; j<=num_conds; j++) {
                    cprefix = fprefix + j + "_";
                    field = get_url_param(cprefix + "field");
                    op = get_url_param(cprefix + "op");
                    v1 = get_url_param(cprefix + "v1");
                    v2 = get_url_param(cprefix + "v2");
                    if(j === 1) {
                        cond = filter.conditions[0]; // first cond is auto-created
                    }
                    else {
                        cond = filter.add_condition();
                    }
                    cond.set(field, op, v1, v2);
                }
            }
        }
    };

    /** Manages a single grouping. */
    function Group(parent, gname, container, n) {
        var me = this, field_choices, op_choices, extra_container, extra_value, extra_value_desc, extra_opt_container, extra_opt, btnRm;
        this.parent = parent;
        this.gname = gname;
        this.container = container;

        // create the default contents of the container node for this group
        this.leading_span = document.createElement('span');
        this.leading_span.appendChild(document.createTextNode('then '));
        container.appendChild(this.leading_span);
        container.appendChild(document.createTextNode('group by '));
        this.renumber(n);

        field_choices = document.createElement('select');
        op_choices = document.createElement('select');
        extra_container = document.createElement('span');
        extra_value = createValueField(gname, '');
        extra_value.setAttribute('size', 3);
        extra_value_desc = document.createTextNode('');
        extra_opt_container = document.createElement('span');
        extra_opt_value = document.createElement('select');

        this.field_choices = field_choices;
        this.op_choices = op_choices;
        this.extra_value = extra_value;
        this.extra_opt_value = extra_opt_value;

        // initialize the field choices combo box
        field_choices.setAttribute('name', gname + '_field');
        field_choices.innerHTML = G_FIELD_OPTIONS;
        field_choices.onchange = function () {
            // show the operators allowed with this kind of field
            op_choices.innerHTML = G_OPERATORS_OPTIONS[field_choices.selectedIndex];
            op_choices.onchange();
        };

        //initialize the operator choices combo box
        op_choices.setAttribute('name', gname + '_op');
        op_choices.onchange = function () {
            // show the number of value fields as appropriate
            var i, op, state;
            op = op_choices.options[op_choices.selectedIndex].innerHTML;
            state = 'none';
            for(i=0; i<G_OP_NEEDS_EXTRA_VALUE.length; i++) {
                if(op === G_OP_NEEDS_EXTRA_VALUE[i]) {
                    state = 'inline';
                    extra_value_desc.nodeValue = G_OP_NEEDS_EXTRA_VALUE_DESC[i] + ' = ';
                    break;
                }
            }
            extra_container.style.display = state;
            state = 'none';
            for(i=0; i<G_OP_HAS_ALIGN_TO_0_OPT.length; i++) {
                if(op === G_OP_HAS_ALIGN_TO_0_OPT[i]) {
                    state = 'inline';
                    break;
                }
            }
            extra_opt_container.style.display = state;
        };

        // initialize the optional dropdown
        extra_opt_value.setAttribute('name', gname + '_opt');
        extra_opt_value.innerHTML = G_ALIGN_TO_0_OPT_OPTIONS;

        // create a button to delete this condition
        btnRm = createOrdinaryButton('X');
        btnRm.onclick = function() { me.remove(); };

        // add each of the new elements to our container
        container.appendChild(op_choices);
        container.appendChild(document.createTextNode(' of '));
        container.appendChild(field_choices);
        extra_container.appendChild(document.createTextNode(' ('));
        extra_container.appendChild(extra_value_desc);
        extra_container.appendChild(extra_value);
        extra_container.appendChild(document.createTextNode(') '));
        container.appendChild(extra_container);
        extra_opt_container.appendChild(extra_opt_value);
        container.appendChild(extra_opt_container);
        container.appendChild(btnRm);

        // trigger onchange() for the default selections
        field_choices.onchange();
    }

    /** deletes this group (removes it from the DOM and from the Groups list) */
    Group.prototype.remove = function () {
        this.container.parentNode.removeChild(this.container);
        this.parent.group_deleted_callback(this);
    };

    /** Changes the number of this group (1 is first). */
    Group.prototype.renumber = function (n) {
        this.leading_span.style.visibility = ((n === 1) ? 'hidden' : 'visible');
    };

    /** Sets the group */
    Group.prototype.set = function (field, op, extra_value, extra_opt_value) {
        this.field_choices.selectedIndex = field;
        this.field_choices.onchange();
        this.op_choices.selectedIndex = op;
        this.op_choices.onchange();
        this.extra_value.value = extra_value;
        this.extra_opt_value.value = extra_opt_value;
    };

    // setup groups
    function Groups(groups_node) {
        var me = this, aggr_field, aggr_op, aggr_container, aggr_extra_container;

        // prefix associated with this filter set for form fields
        this.FORM_PREFIX = prefix + 'group';

        this.container = groups_node;

        this.groups = [];

        // id to use for the next group
        this.next_group_id = 0;

        this.default_contents = document.createElement('div');
        this.default_contents.innerHTML = 'No groups have been specified - all data will be in the same group.';
        this.container.appendChild(this.default_contents);

        this.btnAddGroup = createOrdinaryButton("Add a grouping");
        this.btnAddGroup.onclick = function () { me.add_group(); };
        this.container.appendChild(this.btnAddGroup);

        // setup aggregation form elements
        aggr_container = document.createElement('div');
        aggr_container.setAttribute('name', 'aggr_container');
        aggr_container.innerHTML = '<b>How to aggregate</b>: ';

        aggr_extra_container = document.createElement('span');
        aggr_extra_container.appendChild(document.createTextNode(' of '));
        aggr_field = document.createElement('select');
        aggr_field.setAttribute('name', 'aggr_field');
        aggr_field.innerHTML = A_FIELD_OPTIONS;
        aggr_extra_container.appendChild(aggr_field);

        aggr_op = document.createElement('select');
        aggr_op.setAttribute('name', 'aggr_op');
        aggr_op.innerHTML = A_OPERATORS_OPTIONS;
        aggr_op.onchange = function () {
            // show the number of value fields as appropriate
            var i, op, state;
            op = aggr_op.options[aggr_op.selectedIndex].innerHTML;
            state = 'inline';
            for(i=0; i<AGGR_OPS_NULLARY.length; i++) {
                if(op === AGGR_OPS_NULLARY[i]) {
                    state = 'none';
                    break;
                }
            }
            aggr_extra_container.style.display = state;
        };

        aggr_container.appendChild(aggr_op);
        aggr_container.appendChild(aggr_extra_container);
        this.container.appendChild(aggr_container);
        this.aggr_op = aggr_op;
        this.aggr_field = aggr_field;

        this.populate_from_url();
    }

    /** adds a new subgroup */
    Groups.prototype.add_group = function (gname) {
        var gdiv;
        if(gname === undefined) {
            gname = this.FORM_PREFIX + this.next_group_id;
        }
        gdiv = document.createElement('div');
        this.groups.push(new Group(this, gname, gdiv, this.groups.length+1));
        this.next_group_id += 1;
        this.container.insertBefore(gdiv, this.btnAddGroup);

        // hide the default contents
        this.default_contents.style.display = 'none';
        this.btnAddGroup.innerHTML = 'Add another grouping';
        return this.groups[this.groups.length - 1];
    };

    /** Callback to issue when a group is deleted. */
    Groups.prototype.group_deleted_callback = function (g) {
        var i;
        // remove g from groups
        for(i=0; i<this.groups.length; i++) {
            if(this.groups[i] === g) {
                this.groups.splice(i, 1);
                break;
            }
        }

        // renumber the remaining groups
        for(; i<this.groups.length; i++) {
            this.groups[i].renumber(i+1);
        }

        // show the default contents again if there are no groups left
        if(this.groups.length === 0) {
            this.default_contents.style.display = 'block';
            this.btnAddGroup.innerHTML = 'Add a grouping';
        }
    };

    /** Creates groups and aggregation op from parsed URL parameters. */
    Groups.prototype.populate_from_url = function() {
        var i, field, gprefix, group, num_groups, op, v, ov;

        // handle aggregation
        this.aggr_op.value = get_url_param("aggr_op");
        this.aggr_field.selectedIndex = get_url_param("aggr_field");
        this.aggr_op.onchange();

        num_groups = get_url_param(prefix + "num_groups");
        if(num_groups === null) {
            return; // no groups
        }

        for(i=1; i<=num_groups; i++) {
            gprefix = this.FORM_PREFIX + i + '_';

            field = get_url_param(gprefix + "field");
            op = get_url_param(gprefix + "op");
            v = get_url_param(gprefix + "v");
            ov = get_url_param(gprefix + "opt");

            group = this.add_group();
            group.set(field, op, v, ov);
        }
    };

    /** TODO: manage aggregation form elements */

    // create each of the filter sets
    new FilterSet(true, inclusive_node);
    new FilterSet(false, exclusive_node);
    new Groups(groups_node);
}
