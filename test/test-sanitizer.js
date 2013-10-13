var assert = require("assert");
var sanitizer = require("../src/sanitizer.js");

function nmTokenPolicy(nmTokens) {
    if ("specialtoken" === nmTokens) {
        return nmTokens;
    }
    if (/[^a-z\t\n\r ]/i.test(nmTokens)) {
        return null;
    } else {
        return nmTokens.replace(
            /([^\t\n\r ]+)([\t\n\r ]+|$)/g,
            function (_, id, spaces) {
                return 'p-' + id + (spaces ? ' ' : '');
            });
    }
}

function uriPolicy(value, effects, ltype, hints) {
    if (value && "specialurl" === value.toString()) {
        return value;
    }
    return 'u:' + value.toString();
}

describe('Sanitizer.sanitize', function() {

    it('should sanitize empty', function() {
        assert.equal('', sanitizer.sanitize(''))
    });

    it('should sanitize simple text', function() {
        assert.equal('hello world', sanitizer.sanitize('hello world'))
    });

    it('should sanitize entities', function() {
        assert.equal('&lt;hello world&gt;', sanitizer.sanitize('&lt;hello world&gt;'))
    });

    it('should sanitize more entities', function() {
        assert.equal('&amp;amp&amp;&amp;&amp;amp', sanitizer.sanitize('&amp&amp;&&amp'))
    });

    it('should remove unknown tags', function() {
        assert.equal('<b>hello <i>world</i></b>', sanitizer.sanitize('<u:y><b>hello <bogus><i>world</i></bogus></b>'))
    });

    it('should remove unsafe tags', function() {
        assert.equal('<b>hello <i>world</i></b>', sanitizer.sanitize('<b>hello <i>world</i><script src=foo.js></script></b>'))
    });

    it('should remove unsafe attributes', function() {
        assert.equal('<b>hello <i>world</i></b>', sanitizer.sanitize('<b>hello <i onclick="takeOverWorld(this)">world</i></b>'))
    });

    it('should escape cruft', function() {
        assert.equal('<b>hello <i>world&lt;</i></b> &amp; tomorrow the universe', sanitizer.sanitize('<b>hello <i>world<</i></b> & tomorrow the universe'))
    });

    it('should remove tag cruft', function() {
        assert.equal('<b id="p-foo">hello <i>world&lt;</i></b>', sanitizer.sanitize('<b id="foo" / -->hello <i>world<</i></b>', uriPolicy, nmTokenPolicy))
    });

    it('should prefix ids and classes', function() {
        assert.equal('<b id="p-foo" class="p-boo p-bar p-baz">hello <i>world&lt;</i></b>', sanitizer.sanitize('<b id="foo" class="boo bar baz">hello <i>world<</i></b>', uriPolicy, nmTokenPolicy))
    });

    it('should remove invalid ids and classes', function() {
        assert.equal('<b>hello <i>world&lt;</i></b>', sanitizer.sanitize('<b id="a," class="b c/d e">hello <i class="i*j">world<</i></b>', uriPolicy, nmTokenPolicy))
    });

    it('should prefix usemap', function() {
        assert.equal('<img usemap="#p-foo" src="u:http://bar">', sanitizer.sanitize('<img usemap="#foo" src="http://bar">', uriPolicy, nmTokenPolicy))
    });

    it('should remove invalid usemaps', function() {
        assert.equal('<b>hello <i>world&lt;</i></b>', sanitizer.sanitize('<b id="a," class="b c/d e">hello <i class="i*j">world<</i></b>', uriPolicy, nmTokenPolicy))
        assert.equal('<img src="u:http://bar">', sanitizer.sanitize('<img src="http://bar">', uriPolicy, nmTokenPolicy))
        assert.equal('<img src="u:http://bar">', sanitizer.sanitize('<img usemap="" src="http://bar">', uriPolicy, nmTokenPolicy))
        assert.equal('<img src="u:http://bar">', sanitizer.sanitize('<img usemap="foo" src="http://bar">', uriPolicy, nmTokenPolicy))
    });

    it('should sanitize non-string input', function() {
        var bad = '<b whacky=foo><script src=badness.js></script>bar</b id=foo>';
        assert.equal('<b>bar</b>', sanitizer.sanitize({
            toString: function () {
                return bad;
            }
        }, uriPolicy, nmTokenPolicy))
    });

    it('should sanitize special chars in attributes', function() {
        assert.equal('<b title="a&lt;b &amp;&amp; c&gt;b">bar</b>', sanitizer.sanitize('<b title="a<b && c>b">bar</b>', uriPolicy, nmTokenPolicy));
    });

    it('should sanitize unclosed tags', function() {
        assert.equal('<div id="p-foo">Bar<br>Baz</div>', sanitizer.sanitize('<div id="foo">Bar<br>Baz', uriPolicy, nmTokenPolicy));
    });

    it('should sanitize unopened tags', function() {
        assert.equal('Foo<b>Bar</b>Baz', sanitizer.sanitize('Foo<b></select>Bar</b></b>Baz</select>', uriPolicy, nmTokenPolicy));
    });

    it('should sanitize unsafe end tags', function() {
        assert.equal('', sanitizer.sanitize('</meta http-equiv="refresh" content="1;URL=http://evilgadget.com">', uriPolicy, nmTokenPolicy));
    });

    it('should sanitize empty end tags', function() {
        assert.equal('<input>', sanitizer.sanitize('<input></input>', uriPolicy, nmTokenPolicy));
    });

    it('should strip onload', function() {
        assert.equal('<img src="u:http://foo.com/bar">', sanitizer.sanitize('<img src=http://foo.com/bar ONLOAD=alert(1)>', uriPolicy, nmTokenPolicy));
    });

    it('should sanitize closing tag parameters', function() {
        assert.equal('<p>1<p>2</p><p>3</p>5</p>', sanitizer.sanitize('<p>1</b style="x"><p>2</p /bar><p>3</p title=">4">5', uriPolicy, nmTokenPolicy));
    });

    it('should sanitize optional end tags', function() {
        assert.equal('<ol> <li>A</li> <li>B<li>C </ol>', sanitizer.sanitize('<ol> <li>A</li> <li>B<li>C </ol>', uriPolicy, nmTokenPolicy));
    });

    it('should sanitize folding of html and body tags', function() {
        assert.equal('<p>P 1</p>', sanitizer.sanitize('<html><head><title>Foo</title></head>'
            + '<body><p>P 1</p></body></html>', uriPolicy, nmTokenPolicy));
        assert.equal('Hello', sanitizer.sanitize('<body bgcolor="blue">Hello</body>', uriPolicy, nmTokenPolicy));
        assert.equal('<p>Foo</p><p>One</p><p>Two</p>Three<p>Four</p>', sanitizer.sanitize('<html>'
            + '<head>'
            + '<title>Blah</title>'
            + '<p>Foo</p>'
            + '</head>'
            + '<body>'
            + '<p>One</p>'
            + '<p>Two</p>'
            + 'Three'
            + '<p>Four</p>'
            + '</body>'
            + '</html>', uriPolicy, nmTokenPolicy));
    });

    it('should sanitize empty and valueless attributes', function() {
        assert.equal('<input checked="" type="checkbox" id="" class="">', sanitizer.sanitize('<input checked type=checkbox id="" class=>', uriPolicy, nmTokenPolicy));
        assert.equal('<input checked="" type="checkbox" id="" class="">', sanitizer.sanitize('<input checked type=checkbox id= class="">', uriPolicy, nmTokenPolicy));
       assert.equal('<input checked="" type="checkbox" id="" class="">', sanitizer.sanitize('<input checked type=checkbox id= class = "">', uriPolicy, nmTokenPolicy));
    });

    it('should sanitize SGML short tags', function() {
        assert.equal('', sanitizer.sanitize('<p/b/', uriPolicy, nmTokenPolicy));
        assert.equal('<p>first part of the text&lt;/&gt; second part</p>', sanitizer.sanitize('<p<a href="/">first part of the text</> second part', uriPolicy, nmTokenPolicy));
        assert.equal('<p></p>', sanitizer.sanitize('<p<b>', uriPolicy, nmTokenPolicy));
    });

    it('should sanitize Nul', function() {
        assert.equal('<a title="x  SCRIPT=javascript:alert(1) ignored=ignored"></a>', sanitizer.sanitize('<A TITLE="x\0  SCRIPT=javascript:alert(1) ignored=ignored">', uriPolicy, nmTokenPolicy));
    });

    it('should test digits in attr names', function() {
        assert.equal('<div>Hello</div>', sanitizer.sanitize('<div style1="expression(\'alert(1)\')">Hello</div>', uriPolicy, nmTokenPolicy));
    });
});


//jsunitRegister('testIncompleteTagOpen',
//    function testIncompleteTagOpen() {
//        check1('x<a', 'x');
//        check1('x<a ', 'x');
//        check1('x<a\n', 'x');
//        check1('x<a bc', 'x');
//        check1('x<a\nbc', 'x');
//        jsunit.pass();
//    });
//
//jsunitRegister('testUriPolicy',
//    function testUriPolicy() {
//        assertEquals('<a href="http://www.example.com/">hi</a>',
//            html.sanitize('<a href="http://www.example.com/">hi</a>',
//                function(uri) { return uri; }));
//        assertEquals('<a>hi</a>',
//            html.sanitize('<a href="http://www.example.com/">hi</a>',
//                function(uri) { return null; }));
//        assertEquals('<a>hi</a>',
//            html.sanitize('<a href="javascript:alert(1)">hi</a>',
//                function(uri) { return uri; }));
//        assertEquals('<a>hi</a>',
//            html.sanitize('<a href="javascript:alert(1)">hi</a>',
//                function(uri) { return null; }));
//        assertEquals('<a>hi</a>',
//            html.sanitize('<a href=" javascript:alert(1)">hi</a>',
//                function(uri) { return uri; }));
//        assertEquals('<a>hi</a>',
//            html.sanitize('<a href=" javascript:alert(1)">hi</a>',
//                function(uri) { return null; }));
//        assertEquals('<a href="//www.example.com/">hi</a>',
//            html.sanitize('<a href="//www.example.com/">hi</a>',
//                function(uri) { return uri; }));
//        assertEquals('<a href="foo.html">hi</a>',
//            html.sanitize('<a href="foo.html">hi</a>',
//                function(uri) { return uri; }));
//        assertEquals('<a href="bar/baz.html">hi</a>',
//            html.sanitize('<a href="foo.html">hi</a>',
//                function(uri) { return "bar/baz.html"; }));
//        assertEquals('<a href="mailto:jas@example.com">mail me</a>',
//            html.sanitize('<a href="mailto:jas@example.com">mail me</a>',
//                function(uri) { return uri; }));
//        assertEquals('<a>mail me</a>',
//            html.sanitize('<a href="mailto:jas@example.com">mail me</a>',
//                function(uri) { return null; }));
//
//        assertEquals('<a href="foo.html">test</a>',
//            html.sanitize('<a href="foo.html">test</a>',
//                function(uri, effect, ltype, hints) {
//                    assertEquals("MARKUP", hints.TYPE);
//                    assertEquals("href", hints.XML_ATTR);
//                    assertEquals("a", hints.XML_TAG);
//                    return uri;
//                }));
//        jsunit.pass();
//    });
//
//jsunitRegister('testTagPolicy',
//    function testTagPolicy() {
//        // NOTE: makeHtmlSanitizer / sanitizeWithPolicy is not documented in the wiki
//        // JsHtmlSanitizer doc. However, it is used by Caja and other clients. Changes
//        // to this API should be noted in releases.
//        function checkT(expected, input, tagPolicy) {
//            assertEquals(expected, html.sanitizeWithPolicy(input, tagPolicy));
//        }
//        // pass tag
//        checkT('<a href="http://www.example.com/">hi</a> there',
//            '<a href="http://www.example.com/">hi</a> there',
//            function(name, attribs) {
//                return {attribs: attribs};
//            });
//        // reject tag
//        checkT(' there',
//            '<a href="http://www.example.com/">hi</a> there',
//            function(name, attribs) {
//                return null;
//            });
//        // modify attribs
//        checkT('<a x="y">hi</a> there',
//            '<a href="http://www.example.com/">hi</a> there',
//            function(name, attribs) {
//                return {attribs: ["x", "y"]};
//            });
//        // modify tagName
//        checkT('<xax href="http://www.example.com/">hi</xax> there',
//            '<a href="http://www.example.com/">hi</a> there',
//            function(name, attribs) {
//                return {attribs: attribs, tagName: 'x' + name + 'x'};
//            });
//        function conditionalRewritePolicy(name, attribs) {
//            return {attribs: attribs,
//                tagName: attribs.length ? 'x' + name + 'x' : name};
//        }
//        // proper end-tag matching w/ rewrite
//        checkT('<span>a<xspanx r="1">b</xspanx>c</span>',
//            '<span>a<span r=1>b</span>c</span>',
//            conditionalRewritePolicy);
//        // proper optional-end-tag handling w/ rewrite - siblings
//        // (Note: This example will not sensibly parse as HTML; it is only to stress
//        // the intended algorithm here.)
//        checkT('<ul><li>a</li><xlix r="1">b</xlix></ul>',
//            '<ul><li>a<li r=1>b</li></ul>',
//            conditionalRewritePolicy);
//        // descendant end-tag matching (Ditto.)
//        checkT('<ul><li>a<ul><xlix r="1">b</xlix></ul></li></ul>',
//            '<ul><li>a<ul><li r=1>b</li></ul></li></ul>',
//            conditionalRewritePolicy);
//        jsunit.pass();
//    });
//
//function assertSanitizerMessages(input, expected, messages) {
//    logMessages = [];
//    var actual = html.sanitize(input, uriPolicy, nmTokenPolicy, logPolicy);
//    assertEquals(expected, actual);
//    // legacy sanitizer does not support logging
//    if (!html.isLegacy) {
//        assertEquals(messages.length, logMessages.length);
//        logMessages.forEach(function (val, i) {
//            assertEquals(messages[i], val);
//        });
//    }
//}
//
//jsunitRegister('testLogger',
//    function testLogger() {
//        assertSanitizerMessages('<a href="http://www.example.com/">hi</a>',
//            '<a href=\"u:http://www.example.com/\">hi</a>',
//            ["a.href changed"]);
//        assertSanitizerMessages('<a href="specialurl">hi</a>',
//            '<a href=\"specialurl\">hi</a>',
//            []);
//        assertSanitizerMessages('<div onclick="foo()"></div>',
//            '<div></div>',
//            ["div.onclick removed"]);
//        assertSanitizerMessages(
//            '<div onclick="foo()" class="specialtoken" id=baz></div>',
//            '<div class="specialtoken" id="p-baz"></div>',
//            ["div.onclick removed", "div.id changed"]);
//        assertSanitizerMessages(
//            '<script>alert(1);</script>',
//            '',
//            ["script removed"]);
//        jsunit.pass();
//    });
//
//function assertSAXEvents(htmlSource, param, varargs_golden) {
//    // events is a flat array of triples (type, data, param)
//    var events = [];
//    // makeSaxParser doesn't guarantee how text segments are chunked, so here
//    // we canonicalize the event stream by combining adjacent text events.
//    var addTextEvent = function (type, text, param) {
//        var n = events.length;
//        if (events[n - 3] === type && events[n - 1] === param) {
//            events[n - 2] += text;
//        } else {
//            events.push(type, text, param);
//        }
//    };
//    var saxParser = html.makeSaxParser({
//        startTag: function (name, attribs, param) {
//            events.push('startTag', name + '[' + attribs.join(';') + ']', param);
//        },
//        endTag:   function (name, param) {
//            events.push('endTag', name, param);
//        },
//        pcdata:   function (text, param) {
//            addTextEvent('pcdata', text, param);
//        },
//        cdata:    function (text, param) {
//            addTextEvent('cdata', text, param);
//        },
//        rcdata:   function (text, param) {
//            addTextEvent('rcdata', text, param);
//        },
//        comment:  function (text, param) {
//            events.push('comment', text, param);
//        },
//        startDoc: function (param) {
//            events.push('startDoc', '', param);
//        },
//        endDoc:   function (param) {
//            events.push('endDoc', '', param);
//        }
//    });
//    saxParser(htmlSource, param);
//    var golden = Array.prototype.slice.call(arguments, 2);
//    assertEquals(golden.join("|"), events.join("|"));
//}
//
//jsunitRegister('testSaxParser', function () {
//    assertSAXEvents(
//        "<p id=foo>Foo&amp;Bar</p><script>alert('<b>&amp;</b>')</script>",
//        "<param>",
//
//        'startDoc', '', '<param>',
//        'startTag', 'p[id;foo]', '<param>',
//        'pcdata', 'Foo&amp;Bar', '<param>',
//        'endTag', 'p', '<param>',
//        'startTag', 'script[]', '<param>',
//        'cdata', "alert('<b>&amp;</b>')", '<param>',
//        'endTag', 'script', '<param>',
//        'endDoc', '', '<param>');
//    jsunit.pass();
//});
//
//// legacy parser doesn't have comment events
//// legacy parser doesn't allow _ in attr names
//if (!html.isLegacy) {
//    jsunitRegister('testSaxParserComments', function () {
//        assertSAXEvents(
//            '<some_tag some_attr=x><!--  com>--ment --></some_tag>',
//            '$P',
//
//            'startDoc', '', '$P',
//            'startTag', 'some_tag[some_attr;x]', '$P',
//            'comment', '  com>--ment ', '$P',
//            'endTag', 'some_tag', '$P',
//            'endDoc', '', '$P');
//        jsunit.pass();
//    });
//}
//
//// legacy parser drops unknown tags
//if (!html.isLegacy) {
//    jsunitRegister('testSaxParserUnknownTags', function () {
//        assertSAXEvents(
//            '<div><unknown1><unknown2 bar></unknown1>',
//            '$P',
//            'startDoc', '', '$P',
//            'startTag', 'div[]', '$P',
//            'startTag', 'unknown1[]', '$P',
//            'startTag', 'unknown2[bar;]', '$P',
//            'endTag', 'unknown1', '$P',
//            'endDoc', '', '$P'
//        );
//        jsunit.pass();
//    });
//}
//
//// legacy parser is more restrictive
//if (!html.isLegacy) {
//    jsunitRegister('testSaxParserExpansive', function () {
//        assertSAXEvents(
//            '<x:y 3:.=4></x:y>',
//            '$P',
//            'startDoc', '', '$P',
//            'startTag', 'x:y[3:.;4]', '$P',
//            'endTag', 'x:y', '$P',
//            'endDoc', '', '$P'
//        );
//        jsunit.pass();
//    });
//}
//
//jsunitRegister('testSaxParserConfusingScripts', function () {
//    assertSAXEvents(
//        '<div class="testcontainer" id="test">' +
//            '<script>document.write("<b><script>");</script>' +
//            '<script>document.write("document.write(");</script>' +
//            '<script>document.write("\'Hello,</b> \'");</script>' +
//            '<script>document.write(",\'World!\');<\\/script>");</script>' +
//            '!</div>',
//
//        'PARAM',
//
//        'startDoc', '', 'PARAM',
//        'startTag', 'div[class;testcontainer;id;test]', 'PARAM',
//        'startTag', 'script[]', 'PARAM',
//        'cdata', 'document.write("<b><script>");', 'PARAM',
//        'endTag', 'script', 'PARAM',
//        'startTag', 'script[]', 'PARAM',
//        'cdata', 'document.write("document.write(");', 'PARAM',
//        'endTag', 'script', 'PARAM',
//        'startTag', 'script[]', 'PARAM',
//        'cdata', 'document.write("\'Hello,</b> \'");', 'PARAM',
//        'endTag', 'script', 'PARAM',
//        'startTag', 'script[]', 'PARAM',
//        'cdata', 'document.write(",\'World!\');<\\/script>");', 'PARAM',
//        'endTag', 'script', 'PARAM',
//        'pcdata', '!', 'PARAM',
//        'endTag', 'div', 'PARAM',
//        'endDoc', '', 'PARAM');
//    jsunit.pass();
//});
