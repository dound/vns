/**
 * This function creates dynamic form elements for searching a model.  The input
 * fields it creates will be of the form "<prefix><type><filter#>_<condition#>_<field>"
 * where <type> is either "i" or "e" (inclusive/exclusive filter) and <field>
 * is "field" (index of the field this filter's condition is on), "op" (index of
 * the operator to search the field with), or "v1" or "v2" (search values; v2
 * may only be applicable for some operators).  The field and operator index
 * correspond to the position of elements in the field_infos argument.
 *
 * @param prefix       Text to prefix each input field with
 * @param field_infos  An array of of information about fields.  Each element is
 *                     an array of two items: the name of the field and an array
 *                     of operators it can use.
 * @param inclusive_node  DOM element where inclusive form fields should be put
 * @param exclusive_node  DOM element where exclusive form fields should be put
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

    /**
     * A Condition manages what restrictions are on a single field.
     *
     * @param cname      unique name of this condition
     * @param container  DOM element which will hold this condition's elements
     */
    function Condition(cname, container) {
        var field_choices, op_choices, value1, txtBetweenValues, value2;
        field_choices = document.createElement('select');
        op_choices = document.createElement('select');
        value1 = createValueField(cname, 1);
        txtBetweenValues = document.createTextNode(' to ');
        value2 = createValueField(cname, 2);

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

        // add each of the new elements to our container
        container.appendChild(field_choices);
        container.appendChild(op_choices);
        container.appendChild(value1);
        container.appendChild(txtBetweenValues);
        container.appendChild(value2);

        // trigger onchange() for the default selections
        field_choices.onchange();
    }

    /**
     * A Filter manages a set of conditions.
     *
     * @param parent_fs  FilterSet which is the parent of this Filter
     * @param fname      unique name of this filter
     * @param container  DOM element which will hold this filter's elements
     * @param num        which filter number this is (1 indexed)
     */
    function Filter(parent_fs, fname, container, num) {
        var conditions, next_cond_id, txtJoin, conditions_container, btnAddCondition;

        // conditions associated with this filter (these are AND'ed together)
        conditions = [];

        // id to use for the next condition
        next_cond_id = 0;

        // create the default contents of the container node for this filter
        txtJoin = (num === 1) ? '' : 'OR ';
        container.appendChild(document.createTextNode(txtJoin + 'Filter #' + num));
        conditions_container = document.createElement('blockquote');
        container.appendChild(conditions_container);

        // create a button to add more conditions
        btnAddCondition = createOrdinaryButton('AND ...');
        conditions_container.appendChild(btnAddCondition);

        // adds a new condition to this filter
        function add_condition(first) {
            var cname, cdiv, txtNode, invisible_span;

            // add a new condition to this filter
            cname = fname + '_' + next_cond_id;
            next_cond_id = next_cond_id + 1;
            cdiv = document.createElement('div');
            txtNode = document.createTextNode(' AND ');
            if(first) {
                invisible_span = document.createElement('span');
                invisible_span.style.visibility = 'hidden';
                invisible_span.appendChild(txtNode);
                cdiv.appendChild(invisible_span);
            }
            else {
                cdiv.appendChild(txtNode);
            }
            conditions.push(new Condition(cname, cdiv));
            conditions_container.insertBefore(cdiv, btnAddCondition);
        }

        // create the default condition
        add_condition(true);

        // clicking on the button should create a new condition
        btnAddCondition.onclick = function () { add_condition(false); };

        // callback issued when a condition is deleted from this filter
        function condition_deleted_callback(c) {
            // if the last condition is being removed, then delete this filter
            if(conditions.length === 1) {
                parent_fs.filter_deleted_callback(this);
            }
            else {
                // remove c from our list of conditions
                // TODO ...

                // renumber remaining conditions
                // TODO ...
            }
        }
    }

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
    }

    /** Add a filter to the filter set. */
    FilterSet.prototype.add_filter = function () {
        var fname, fdiv;
        fname = this.FORM_PREFIX + this.next_filter_id;
        fdiv = document.createElement('div');
        this.filters.push(new Filter(this, fname, fdiv, this.filters.length+1));
        this.next_filter_id += 1;
        this.container.insertBefore(fdiv, this.btnAddFilter);

        // hide the default contents
        this.default_contents.style.display = 'none';
        this.btnAddFilter.innerHTML = 'Add another filter';
    };

    /** Callback to issue when a filter from this set is deleted. */
    FilterSet.prototype.filter_deleted_callback = function (f) {
        // remove f from filters
        // TODO ...

        // renumber the remaining filters
        // TODO ...
    };

    // create each of the filter sets
    new FilterSet(true, inclusive_node);
    new FilterSet(false, exclusive_node);
}
