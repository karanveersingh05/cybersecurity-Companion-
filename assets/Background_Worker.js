// Background_Worker.js
// ENGINE: DOM Scanner — Synchronous Chunked Extraction
//
// FIX: Qt6's runJavaScript() callback ONLY receives synchronous return values.
// An `async` function returns a Promise object, which Qt serialises as undefined/null.
// Solution: Use synchronous iteration with a node budget cap to avoid
// blocking the Chromium thread for too long on any single call.

(function() {
    var MAX_NODES = 5000;  // Hard cap to prevent memory/time blowout on huge pages
    var count = 0;

    function walk(node) {
        if (!node || count >= MAX_NODES) return "";

        // Text node — escape and return content
        if (node.nodeType === 3) {
            count++;
            return node.textContent
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;');
        }

        // Only process element nodes
        if (node.nodeType !== 1) return "";

        count++;

        var tag = node.tagName.toLowerCase();

        // Skip style/script body content to reduce payload size
        if (tag === 'script' || tag === 'style') {
            return '<' + tag + '></' + tag + '>';
        }

        var attrs = "";
        for (var i = 0; i < node.attributes.length; i++) {
            var attr = node.attributes[i];
            var val = attr.value.replace(/"/g, '&quot;');
            attrs += ' ' + attr.name + '="' + val + '"';
        }

        var html = '<' + tag + attrs + '>';
        var children = node.childNodes;
        for (var j = 0; j < children.length; j++) {
            if (count >= MAX_NODES) break;
            html += walk(children[j]);
        }
        html += '</' + tag + '>';
        return html;
    }

    return walk(document.documentElement);
})();
