/**
 * ModelSearch creates dynamic form elements for searching a model.  The input
 * fields it creates will be of the form "<type><filter#>_<condition#>_<field>"
 * where <type> is either "i" or "e" (inclusive/exclusive filter) and <field>
 * is "field" (index of the field this filter's condition is on), "op" (index of
 * the operator to search the field with), or "v1" or "v2" (search values; v2
 * may only be applicable for some operators).  The field and operator index
 * correspond to the position of elements in the field_infos argument.
 *
 * @param field_infos  An array of of information about fields.  Each element is
 *                     an array of two items: the name of the field and an array
 *                     of operators it can use.
 * @param inclusive_node  DOM element where inclusive form fields should be put
 * @param exclusive_node  DOM element where exclusive form fields should be put
 */
function ModelSearch(field_infos, inclusive_node, exclusive_node) {
    // build option element html for field options and fields' operator options
    var FIELD_OPTIONS = '';
    var OPERATORS_OPTIONS = [];
    for(var i=0; i<field_infos.length; i++) {
        var field_info = field_infos[i];
        var field_name = field_info[0];
        FIELD_OPTIONS += "<option value='" + i + "'>" + field_name + "</option>";

        var field_ops = field_info[1];
        var OPERATOR_OPTIONS = '';
        for(var j=0; j<field_ops.length; j++) {
            var op_name = field_ops[j];
            OPERATOR_OPTIONS += "<option value ='" + j + "'>" + op_name + "</option";
        }
        OPERATORS_OPTIONS[i] = OPERATOR_OPTIONS;
    }

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
        var field_choices = document.createElement('select');
        var op_choices = document.createElement('select');
        var value1 = createValueField(cname, 1);
        var txtBetweenValues = document.createTextNode(' to ');
        var value2 = createValueField(cname, 2);

        // initialize the field choices combo box
        field_choices.setAttribute('name', cname + '_field');
        field_choices.innerHTML = FIELD_OPTIONS;
        field_choices.onchange = function() {
            // show the operators allowed with this kind of field
            op_choices.innerHTML = OPERATORS_OPTIONS[field_choices.selectedIndex];
            op_choices.onchange();
        };

        //initialize the operator choices combo box
        op_choices.setAttribute('name', cname + '_op');
        op_choices.onchange = function() {
            // show the number of value fields as appropriate
            var op = op_choices.options[op_choices.selectedIndex].innerHTML;
            var state = (op == 'range') ? 'inline' : 'none';
            txtBetweenValues.nodeValue = (state == 'inline') ? ' to ' : '';
            value2.style.display = state;
        }

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
     * @param fname      unique name of this filter
     * @param container  DOM element which will hold this filter's elements
     * @param num        which filter number this is (1 indexed)
     */
    function Filter(fname, container, num) {
        // conditions associated with this filter (these are AND'ed together)
        var conditions = [];

        // id to use for the next condition
        var next_cond_id = 0;

        // create the default contents of the container node for this filter
        var txtJoin = (num == 1) ? '' : 'OR ';
        container.appendChild(document.createTextNode(txtJoin + 'Filter #' + num));
        var conditions_container = document.createElement('blockquote');
        container.appendChild(conditions_container);

        // adds a new condition to this filter
        function add_condition(first) {
            // add a new condition to this filter
            var cname = fname + '_' + next_cond_id;
            next_cond_id = next_cond_id + 1;
            var cdiv = document.createElement('div');
            var txtNode = document.createTextNode(' AND ');
            if(first) {
                var invisible_span = document.createElement('span');
                invisible_span.style.visibility = 'hidden';
                invisible_span.appendChild(txtNode);
                cdiv.appendChild(invisible_span);
            }
            else
                cdiv.appendChild(txtNode);
            conditions.push(new Condition(cname, cdiv));
            conditions_container.insertBefore(cdiv, btnAddCondition);
        };

        // create the default condition
        add_condition(true);

        // create a button to add more conditions
        var btnAddCondition = createOrdinaryButton('AND ...');
        btnAddCondition.onclick = function() { add_condition(false); };
        conditions_container.appendChild(btnAddCondition);
    }

    /**
     * A FilterSet manages a set of filters and their conditions.
     *
     * @param inclusive  boolean which says whether this is the in/exclusive set
     * @param container  DOM node element to populate with the filters
     */
    function FilterSet(inclusive, container) {
        // prefix associated with this filter set for form fields
        var FORM_PREFIX = inclusive ? 'i' : 'e';

        // filters associated with this set (these are OR'ed together)
        var filters = [];

        // id to use for the next filter
        var next_filter_id = 0;

        // initial contents
        var default_contents = document.createElement('div');
        if(inclusive)
            default_contents.innerHTML = 'No filters specified: all records will be included.';
        else
            default_contents.innerHTML = 'No filters specified: no records will be filtered out from the inclusive filter results.';
        container.appendChild(default_contents);

        // create the default contents of the filter set's container node
        var btnAddFilter = createOrdinaryButton('Add a filter');
        btnAddFilter.onclick = function() {
            // add a new filter to this filter set
            var fname = FORM_PREFIX + next_filter_id;
            var fdiv = document.createElement('div');
            filters.push(new Filter(fname, fdiv, filters.length+1));
            next_filter_id = next_filter_id + 1;
            container.insertBefore(fdiv, btnAddFilter);

            // hide the default contents
            default_contents.style.display = 'none';
            btnAddFilter.innerHTML = 'Add another filter';
        };
        container.appendChild(btnAddFilter);
    }

    // create each of the filter sets
    var inclFS = new FilterSet(true, inclusive_node);
    var exclFS = new FilterSet(false, exclusive_node);
}
