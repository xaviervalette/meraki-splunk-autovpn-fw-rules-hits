// Paint the whole row yellow when the "Hits" cell is 0.
require(["jquery", "splunkjs/mvc/simplexml/ready!"], function ($) {
    var ROW_CLASS = "meraki-zero-hits";
    var pending = null;

    function markZeroHitRows() {
        pending = null;
        $("#rules_table_viz table").each(function () {
            var $table = $(this);
            var hitsCol = $table.find("thead th").filter(function () {
                return $.trim($(this).text()) === "Hits";
            }).index();
            if (hitsCol < 0) {
                return;
            }
            $table.find("tbody tr").each(function () {
                var hits = $.trim($(this).children("td").eq(hitsCol).text());
                $(this).toggleClass(ROW_CLASS, hits === "0");
            });
        });
    }

    var panel = document.getElementById("rules_table_viz");
    if (!panel) {
        return;
    }
    // The table re-renders on search refresh, sort and paging: re-mark each time.
    new MutationObserver(function () {
        if (!pending) {
            pending = setTimeout(markZeroHitRows, 50);
        }
    }).observe(panel, { childList: true, subtree: true });
    markZeroHitRows();
});
