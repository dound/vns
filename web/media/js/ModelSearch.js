/**
 * This function creates dynamic form elements for searching a model.  The input
 * fields it creates will be of the form "<prefix><type><filter#>_<condition#>_<field>"
 * where <type> is either "i" or "e" (inclusive/exclusive filter) and <field>
 * is "field" (index of the field this filter's condition is on), "op" (index of
 * the operator to search the field with), or "v1" or "v2" (search values; v2
 * may only be applicable for some operators).  The field and operator index
 * correspond to the position of elements in the field_infos argument.
 *
 * URL parameters can be used to initialize the filters.  To have filters
 * automatically created pass the following parameters:
 *     <prefix><type>_num_filters - number of filters to create
 *     <prefix><type><filter#>_num_conds - number of conditions for the specified filter
 *     <prefix><type><filter#>_<cond#>_<op> - specifies a condition for the specified filter
 *     note: filters and conditions must be numbered from 1 to n.
 *
 * @param prefix       Text to prefix each input field with
 * @param field_infos  An array of of information about fields.  Each element is
 *                     an array of two items: the name of the field and an array
 *                     of operators it can use.
 * @param inclusive_node  DOM element where inclusive form fields should be put
 * @param exclusive_node  DOM element where exclusive form fields should be put
 *
 * @author David Underhill (http://www.dound.com)
 */
function createModelSearch(prefix, field_infos, inclusive_node, exclusive_node) {
    // build option element html for field options and fields' operator options
    var FIELD_OPTIONS, OPERATORS_OPTIONS, OPERATOR_OPTIONS;
    (function () { // create extra vars within a private scope ...
        var i, j, field_info, field_name, field_ops, op_name;
        FIELD_OPTIONS = '';
        OPERATORS_OPTIONS = [];
        for(i=0; i<field_infos.length; i++) {
            field_info = field_infos[i];
            field_name = field_info[0];
            FIELD_OPTIONS += "<option value='" + i + "'>" + field_name + "</option>";

            field_ops = field_info[1];
            OPERATOR_OPTIONS = '';
            for(j=0; j<field_ops.length; j++) {
                op_name = field_ops[j];
                OPERATOR_OPTIONS += "<option value ='" + j + "'>" + op_name + "</option";
            }
            OPERATORS_OPTIONS[i] = OPERATOR_OPTIONS;
        }
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
        var me, txtNode, field_choices, op_choices, value1, txtBetweenValues, value2, btnRm;
        me = this;
        this.parent_filter = parent_filter;
        this.container = container;

        txtNode = document.createTextNode(' AND ');
        this.leading_span = document.createElement('span');
        this.leading_span.appendChild(txtNode);
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
        field_choices.innerHTML = FIELD_OPTIONS;
        field_choices.onchange = function () {
            // show the operators allowed with this kind of field
            op_choices.innerHTML = OPERATORS_OPTIONS[field_choices.selectedIndex];
            op_choices.onchange();
        };

        //initialize the operator choices combo box
        op_choices.setAttribute('name', cname + '_op');
        op_choices.onchange = function () {
            // show the number of value fields as appropriate
            var op, state;
            op = op_choices.options[op_choices.selectedIndex].innerHTML;
            state = (op === 'range') ? 'inline' : 'none';
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
        this.op_choices.selectedIndex = op;
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

    // create each of the filter sets
    new FilterSet(true, inclusive_node);
    new FilterSet(false, exclusive_node);
}
