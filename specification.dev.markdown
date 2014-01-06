<section id="abstract">
This specification defines a mechanism by which user agents may verify that
a fetched resource has been delivered without unexpected manipulation.
</section>

<section id="sotd">
A list of changes to this document may be found at <https://github.com/#TODO>.
</section>

<section class="informative">
## Introduction

It is rare indeed to find a self-contained document on the web. Instead, we
interact with collages of resources loaded from a variety of origins. User
agents fetch these resources blindly; data that comes in is accepted as
canonical, rendered or executed, and cached. Authors must trust that the
resource their content delivery network delivers is in fact the same resource
they expect. If an attacker can trick a user into downloading content from
a different server (via DNS poisioning, or other such means), the author has
no recourse. Likewise, an attacker who can replace the file on the CDN server
has the ability to inject arbitrary content.

We can mitigate the risk of these kinds of attacks by allowing authors to
more clearly explain to the user agent _exactly_ which resource they intend
to load. If an author can provide integrity metadata above and beyond the
bare URL, then the user agent can validate that the data fetched from the
URL provied actually matches the authors' intent.

This document specifies such a validation scheme, extending several HTML
elements with a `integrity` attribute that contains a cryptographic hash of
the contents of the resource the author expects to load. For instance, an
author may wish to load jQuery from a shared server rather than hosting it
on their own origin. Specifying that the _expected_ SHA-256 hash of
`https://code.jquery.com/jquery-1.10.2.min.js`
is `C6CB9UYIS9UJeqinPHWTHVqh_E1uhG5Twh-Y5qFQmYg` means
that the user agent can verify that the data it loads from that URL matches
that expected hash before executing the JavaScript it contains. This
integrity verification significantly reduces the risk that an attacker can
substitute malicious content.

This example can be communicated to a user agent by adding the hash to a
`script` element, like so:

    <script src="https://code.jquery.com/jquery-1.10.2.min.js"
            integrity="ni:///sha-256;C6CB9UYIS9UJeqinPHWTHVqh_E1uhG5Twh-Y5qFQmYg">

The mechanism specified here may also be useful for purposes other than
validation. User agents may decide to use the integrity metadata as an
identifier in a local cache, for instance, meaning that common resources
(for example, JavaScript libraries) could be cached and retrieved regardless
of their URL.

<section>
### Goals

1.  Provide authors with a mechanism of reducing the ambient authority
    of a host (e.g. a content delivery network, or a social network that
    provides widgets) from whom they wish to include JavaScript. Authors
    should be able to grant authority to load _a_ script, not _any_
    script, and compromise of the third-party service should not
    automatically mean compromise of every site which includes its
    scripts.

2.  Improved cachability of common resources: if the user agent downloads
    jQuery once, it shouldn't have to download it again, even if it comes
    from a new URL.

3.  (potentially) Relax mixed-content warnings for resources whose
    integrity is verified.

I'm not sure about #3. Get more detail from the WG about the benefits that
a fallback system would enable. (mkwst)
{:.todo}
</section><!-- /Introduction::Goals -->

<section>
### Use Cases/Examples

*   An author wants to include JavaScript provided by a third-party
    analytics service on her site. She wants, however, to ensure that only
    the code she's carefully reviewed is executed. She can do so by generating
    [integrity metadata][] for the script she's planning on including, and
    adding it to the `script` element she includes on her page:

        <script src="https://analytics-r-us.com/include.js"
                integrity="ni:///sha-256;SDfwewFAE...wefjijfE"></script>

*   A software distribution service wants to ensure that files are correctly
    downloaded. It can do so by adding [integrity metadata][] to the `a`
    elements which users click on to trigger a download:

        <a href="https://software-is-nice.com/awesome.exe"
           integrity="ni:///sha-256;fkfrewFRFEFHJR...wfjfrErw"
           download>...</a>

*   An advertising network wishes to ensure that third-party content only
    is pushed to users after review. They can ensure that only reviewed code is
    delivered by adding [integrity metadata][] to the `iframe` element wrapping
    the advertisement:
    
        <iframe src="https://awesome-ads.com/advertisement1.html"
                integrity="ni:///sha-256;kasfdsaffs...eoirW-e"></iframe>

</section><!-- /Introduction::Use Cases -->
</section><!-- /Introduction -->

<section id="conformance">
Conformance requirements phrased as algorithms or specific steps can be
implemented in any manner, so long as the end result is equivalent. In
particular, the algorithms defined in this specification are intended to
be easy to understand and are not intended to be performant. Implementers
are encouraged to optimize.

<section>
### Key Concepts and Terminology

This section defines several terms used throughout the document.

The term <dfn>digest</dfn> refers to the base64url-encoded result of
executing a cryptographic hash function on an arbitrary block of data.

A <dfn>secure channel</dfn> is any communication mechanism that the user
agent has defined as "secure" (typically limited to HTTP over Transport
Layer Security (TLS) [[!RFC2818]]).

An <dfn>insecure channel</dfn> is any communication mechanism other than
those the user agent has defined as "secure".

The term <dfn>origin</dfn> is defined in the Origin specification.
[[!RFC6454]]

The <dfn>MIME type</dfn> of a resource is a technical hint about the use
and format of that resource. [[!MIMETYPE]]

The <dfn>entity body</dfn>, <dfn>transfer encoding</dfn>, <dfn>content
encoding</dfn> and <dfn>message body</dfn> of a resource is defined by the
[HTTP 1.1 specification, section 7.2][entity]. [[!HTTP11]]

[entity]: http://www.w3.org/Protocols/rfc2616/rfc2616-sec7.html

A <dfn>base64url encoding</dfn> is defined in
[RFC 4648, section 5][base64url]. In a nutshell, it replaces the characters
U+002B PLUS SIGN (`+`) and U+002F SOLIDUS (`/`) characters in normal base64
encoding with the U+002D HYPHEN-MINUS (`-`) and U+005F LOW LINE (`_`)
characters, respectively. [[!RFC4648]]

[base64url]: http://tools.ietf.org/html/rfc4648#section-5

The Augmented Backus-Naur Form (ABNF) notation used in this document is
specified in RFC 5234. [[!ABNF]]

The <dfn>SHA-256</dfn>, <dfn>SHA-384</dfn>, and <dfn>SHA-512</dfn> are part
of the <dfn>SHA-2</dfn> set of cryptographic hash functions defined by the
NIST in ["Descriptions of SHA-256, SHA-384, and SHA-512"][sha].

[abnf-b1]: http://tools.ietf.org/html/rfc5234#appendix-B.1
[sha]: http://csrc.nist.gov/groups/STM/cavp/documents/shs/sha256-384-512.pdf
</section>
</section>

<section>
## Framework

The integrity verification mechanism specified here boils down to the
process of generating a sufficiently strong cryptographic digest for a
resource, and transmitting that digest to a user agent so that it may be
used when fetching the resource.

<section>
### Integrity metadata

To verify the integrity of a resource, a user agent requires <dfn>integrity
metadata</dfn>, which consists of the following pieces of information:

* cryptographic hash function
* [digest][]
* the resource's MIME type

The hash function and digest MUST be provided in order to validate a
resource's integrity. The MIME type SHOULD be provided, as it mitigates the
risk of certain attack vectors (see [MIME Type confusion][] in
this document's Security Considerations section).

This metadata is generally encoded as a "named information" (`ni`) URI, as
defined in RFC6920. [[!RFC6920]]

For example, given a resource containing only the string "Hello, world!",
an author might choose [SHA-256][sha2] as a hash function.
`-MO_YqmqPm_BYZwlDkir51GTc9Pt9BvmLrXcRRma8u8` is the base64url-encoded
digest that results. This can be encoded as an `ni` URI as follows:

    ni:///sha-256;-MO_YqmqPm_BYZwlDkir51GTc9Pt9BvmLrXcRRma8u8

Or, if the author further wishes to specify the content type (`text/plain`):

    ni:///sha-256;-MO_YqmqPm_BYZwlDkir51GTc9Pt9BvmLrXcRRma8u8?ct=text/plain

<div class="note">
Digests may be generated using any number of utilities. [OpenSSL][], for
example, is quite commonly available. The example in this section is the
result of the following command line:

    echo -n "Hello, world." | openssl dgst -sha256 -binary | openssl enc -base64 | sed -e 's/+/-/g' -e 's/\//_/g'

[openssl]: http://www.openssl.org/
</div>

[sha2]: #dfn-sha-2
[digest]: #dfn-digest
[integrity metadata]: #dfn-integrity-metadata
</section><!-- /Framework::Required metadata -->

<section>
### Cryptographic hash functions

Conformant user agents MUST support the [SHA-256][sha2] and [SHA-512][sha2]
cryptographic hash functions for use as part of a resource's
[integrity metadata][].
</section><!-- /Framework::Cryptographic hash functions -->

<section>
### Resource verification algorithms

<section>
#### Apply <var>algorithm</var> to <var>resource</var>

1.  If <var>algorithm</var> is not a hash function recognized and supported
    by the user agent, return `null`.
2.  Let <var>result</var> be the result of applying <var>algorithm</var> to
    the content of the [entity body][] of <var>resource</var>, including any
    content coding that has been applied, but not including any
    transfer encoding applied to the message body.
3.  Let <var>encodedResult</var> be result of base64url-encoding
    <var>result</var>.
4.  Strip any trailing U+003D EQUALS SIGN (`=`) characters from
    <var>encodedResult</var>.
5.  Return <var>encodedResult</var>.

TODO: #2 is pulled from the `content-md5` definition in [[!HTTP11]]. It's
unclear that it's what we want. See  [bzbarsky's WG post on this topic][bz]
{:.todo}

[apply-algorithm]: #apply-algorithm-to-resource
</section>
<section>
#### Does <var>resource</var> match <var>metadata</var>?

1.  If <var>metadata</var> is the empty string, return `true`.
2.  If <var>resource</var>'s scheme is `about`, return `true`.
3.  If <var>metadata</var> is not a valid "named information" (`ni`) URI,
    return `false`.
4.  Let <var>algorithm</var> be the <var>alg</var> component of
    <var>metadata</var>.
5.  Let <var>expectedValue</var> be the <var>val</var> component of
    <var>metadata</var>.
6.  Let <var>expectedType</var> be the value of <var>metadata</var>'s `ct`
    query string parameter.
7.  If <var>expectedType</var> is not the empty string, and is not a
    case-insensitive match for <var>resource</var>'s MIME type,
    return `false`.
8.  Let <var>actualValue</var> be the result of [applying
    <var>algorithm</var> to <var>resource</var>][apply-algorithm].
9.  If <var>actualValue</var> is `null`, return `false`.
10. If <var>actualValue</var> is a case-sensitive match for
    <var>expectedValue</var>, return `true`. Otherwise, return `false`.

If <var>expectedType</var> is the empty string in #6, it would
be reasonable for the user agent to warn the page's author about the
dangers of MIME type confusion attacks via its developer console.
{:.note}

[match]: #does-resource-match-metadata
</section>
</section>

<section>
### Verification of HTML document subresources

A variety of HTML elements result in requests for resources that are to be
embedded into the document, or executed in its context. To support integrity
metadata for each of these, and new elements that are added in the future,
a new `integrity` attribute is added to HTML5's list of
[global attributes][global] that MAY be specified on any HTML element, and
a corresponding attribute is added to the [<code>HTMLElement</code>
interface][htmlelement].

[global]: http://www.w3.org/TR/html5/dom.html#global-attributes
[htmlelement]: http://www.w3.org/TR/html5/dom.html#htmlelement

<section>
#### The `integrity` attribute

The `integrity` attribute represents [integrity metadata][] for an element.
The value of the attribute MUST be either the empty string, or a valid "named
information" (`ni`) URI. [[!RFC6920]]

The `integrity` IDL attribute must [reflect][] the `integrity` content attribute.

[reflect]: http://www.w3.org/TR/html5/infrastructure.html#reflect
</section><!-- /Framework::HTML::integrity -->

<section>
#### The `noncanonical-src` attribute
[noncanonical]: #the-noncanonical-src-attribute

<div class="todo">
The idea is that conformant browsers would first try to load resources from
the `noncanonical-src` attribute's URL iff a `integrity` attribute is present.
Then, if the resource failed to match the digest, the user agent would
fall back to the `src` attribute's URL. That is:

    <script src="http://example.com/script.js"
            noncanonical-src="http://cdn.example.com/script.js"
            integrity="ni:///sha-256;jsdfhiuwergn...vaaetgoifq"></script>

The noncanonical resource would be fetched with its [omit credentials
mode][] set to `always`, to prevent leakage of cookies across insecure
channels.

[omit credentials mode]: http://fetch.spec.whatwg.org/#concept-request-omit-credentials-mode

This only makes sense if we care about allowing cache-friendly (read "HTTP")
URLs to load in an HTTPS context without warnings. I'm not sure we do, so
I'm not going to put too much thought into the details here before we
discuss things a bit more. (mkwst)
</div>

</section><!-- /Framework::HTML::noncanonical-src -->

<section>
#### HTMLElement extension

attribute DOMString integrity
: The value of this element's `integrity` attribute
{:title="partial interface HTMLElement"}
{:.idl}
</section><!-- /Framework::HTML::HTMLElement -->

<section>
#### Handling integrity violations

Documents may specify the behavior of a failed integrity check by delivering
a [Content Security Policy][csp] which contains an `integrity-policy`
directive, defined by the following ABNF grammar:

    directive-name: "integrity-policy"
    directive-value: "block" / "report" / "fallback"

A documents's <dfn>integrity policy</dfn> is the value of the
`integrity-policy` directive, if explicitly provided as part of the
document's Content Security Policy, or `block` otherwise.

If the document's integrity policy is `block`, the user agent MUST refuse to
render or execute resources that fail an integrity check, <em>and</em> MUST
[report a violation][].

If the document's integrity policy is `report`, the user agent MAY render or
execute resources that fail an integrity check, <em>but</em> MUST
[report a violation][].

If the document's integrity policy is `fallback`, the user agent MUST refuse
to render or execute resources that fail an integrity check, <em>and</em>
MUST [report a violation][]. The user agent MAY additionally choose to load
a fallback resource as specified for each relevant element. If the fallback
resource fails an integrity check, the user agent MUST refuse to render or
execute the resource, <em>and</em> MUST [report a(nother)
violation][report a violation]. (See [the `noncanonical-src`
attribute][noncanonical] for a strawman of how that might look).
{:.todo}

[csp]: http://w3.org/TR/CSP11
[report a violation]: http://www.w3.org/TR/CSP11/#dfn-report-a-violation
[integrity policy]: #dfn-integrity-policy
</section>

<section>
##### Elements

<section>
###### The `a` element

If an `a` element has a non-empty `integrity` attribute, then, when handling the
resource the link points to [as a download][], perform the following step before
providing a user with a way to save the resource for later use:

*   If the resource [does not match][match] the integrity metadata specified in
    the `a` element's `integrity` attribute, the user agent MUST [report a
    violation][], <em>and</em> MUST abort the download if the document's
    [integrity policy][] is `block`.

<div class="note">
Note that this should cover both downloads triggered by HTTP headers like
`Content-Disposition`, and also downloads triggered by a `download` attribute
on the `a` element. It might look like the following:

    <a href="https://example.com/file.zip"
       integrity="ni:///sha256;skjdsfkafinqfb...ihja_gqg"
       download>Download!</a>
</div>


[as a download]: http://www.w3.org/TR/html5/links.html#as-a-download
</section><!-- /Framework::HTML::a -->

<section>
###### The `iframe` element

When content is to be loaded into the [child browsing context][] created
by an `iframe` element that has a non-empty `integrity` attribute:

*   The user agent MUST delay rendering the content until the
    [fetching algorithm][]'s task to [process request end-of-file][]
    completes.
*   When the [process request end-of-file][] task completes:
    1.  Let <var>metadata</var> be the value of the document's browsing context
        owner `iframe` element's `integrity` attribute.
    2.  Let <var>resource</var> be the response returned from the fetching
        algorithm.
    3.  If [<var>resource</var> does not match <var>metadata</var>][match]:
        1. If <var>resource</var> is [CORS same-origin][] with the document's
           browsing context owner `iframe` element's Document, then
           [queue a task][] to [fire a simple event][] named `error` at the
           `iframe` element (this will not fire for cross-origin requests, to
           avoid leaking data about those resource's content).
        2. [Navigate][] the child browsing context to `about:blank`.

How does this effect things like the preload scanner? How much work is it
going to be for vendors to change the "display whatever we've got, ASAP!"
behavior that makes things fast for users? How much impact will there be
on user experience, especially for things like ads, where this kind of
validation has the most value?
{:.todo}

How do we deal with navigations in the child browsing context? Are they
simply disallowed? If so, does that make sense? It might for ads, but
what about other use-cases?
{:.todo}

[child browsing context]: http://www.w3.org/TR/html5/browsers.html#child-browsing-context
[navigate]: http://www.w3.org/TR/html5/browsers.html#navigate
[process request end-of-file]: http://fetch.spec.whatwg.org/#process-request-end-of-file
</section><!-- /Framework::HTML::iframe -->

<section>
###### The `link` element

Whenever a user agent attempts to [obtain a resource][] pointed to by a
`link` element that has a non-empty `integrity` attribute, perform the
following steps before firing a `load` event at the element:

1.  Let <var>metadata</var> be the value of the `link` element's
    `integrity` attribute.
2.  Let <var>resource</var> be the response returned from the fetching
    algorithm.
3.  If [<var>resource</var> does not match <var>metadata</var>][match]:
    1.  Abort the `load` event, and treat the resource as having failed to
        load.
    2.  If <var>resource</var> is [CORS same-origin][] with the `link`
        element's Document, then [queue a task][] to [fire a simple event][]
        named `error` at the `link` element (this will not fire for cross-origin
        requests, to avoid leaking data about those resource's content).

[obtain a resource]: http://www.w3.org/TR/html5/document-metadata.html#concept-link-obtain
[cors same-origin]: http://www.w3.org/TR/html5/infrastructure.html#cors-same-origin
</section><!-- /Framework::HTML::link -->

<section>
###### The `script` element

Insert the following steps after step 5 of step 14 of HTML5's
["prepare a script" algorithm][prepare]:

6.  Let <var>metadata</var> be the value of the element's `integrity`
    attribute.
7.  If <var>metadata</var> is the empty string, skip the remaining steps.
8.  Once the [fetching algorithm][] has completed:
    1.  Let <var>resource</var> be the response returned from the fetching
        algorithm.
    2.  If [<var>resource</var> does not match <var>metadata</var>][match]:
        1.  If the document's [integrity policy][] is `block`, [queue a
            task][] to [fire a simple event][] named `error`
            at the element, and abort these steps.
        2.  If the document's [integrity policy][] is `fallback`...
{:start="6"}

[prepare]: http://www.w3.org/TR/html5/scripting-1.html#prepare-a-script
[fetching algorithm]: http://www.w3.org/TR/html5/infrastructure.html#fetch
[queue a task]: http://www.w3.org/TR/html5/webappapis.html#queue-a-task
[fire a simple event]: http://www.w3.org/TR/html5/webappapis.html#fire-a-simple-event
[entity body]: #dfn-entity-body
[bz]: http://lists.w3.org/Archives/Public/public-webappsec/2013Dec/0048.html
</section><!-- /Framework::HTML::Elements::script -->

<section>
###### The `every-other` element

<div class="todo">
TODO: `script` is a good start, but at a minimum, we'll need to cover the
following set of elements:

* audio
* embed
* img
* object
* source
* video
</div>
</section><!-- /Framework::HTML::Elements::* -->

</section><!-- /Framework::HTML::Elements -->

</section><!-- /Framework::HTML -->

<section>
### Verification of CSS-loaded subresources

<div class="note">
Two strawmen. We should poke someone like Tab about these; he'll have
ideas. Or at least opinions.

Idea #1: add an `@integrity` block at the beginning of a CSS file that
contains a list of `@resource` rules, each containing a `url()` and a
`integrity()`. Something like:

    @integrity {
        @resource: url(http://example.com/cat.gif)
                   integrity(ni:///sha-256;3587cb776ce0e4...c838c423);
        @resource: url(http://not-example.com/another-cat.gif)
                   integrity(ni:///sha-256;kljhfigrregq34...298jndkd);
    }

Idea #2: add a `integrity()` to each instance where we load a URL (this
is a poor general solution because repetition, but might work for
one-offs if we think those are more likely). Something like:

    .awesomeness {
        background-image: url(http://example.com/cat.gif)
                          integrity(ni:///sha-256;3587cb776ce0e4...c838c423);
    }

or

    @font-face {
        font-family: IntegralFont;
        src: url(font.woff)
             integrity(ni:///sha-256;3587cb776ce0e4...c838c423);
    }

Hope someone else has better ideas.

---

Tab suggested that idea #1 is bad, as it would be quite fragile and easy
for authors to add or change resources without updating the integrity
section.

I think he's suggested something like:

    .awesomeness {
        background-image: integrity(<url>, <metadata>);
    }
    
Following up with him for clarification.
</div>

</section><!-- /Framework::CSS -->

<section>
### Verification of JS-loaded subresources

<section>
#### Workers

To validate the integrity of scripts which are to be run as workers, a new
constructor is added for `Worker` and `SharedWorker` which accpets a second
argument containing integrity metadata. This information is used when
[running a worker][runworker] to perform validation, as outlined in the
following sections: [[!WEBWORKERS]]

[runworker]: http://dev.w3.org/html5/workers/#run-a-worker

<section>
#### Worker extension

attribute DOMString integrity
: The value of the Worker's `integrity` attribute. Defaults to the empty string.
{:title="[Constructor (DOMString scriptURL, DOMString integrityMetadata)] partial interface Worker : EventTarget"}
{:.idl}

When the `Worker(scriptURL, integrityMetadata)` constructor is invoked:

1. If `integrityMetadata` is not a valid "named information" (`ni`) URL,
   throw a `SyntaxError` exception and abort these steps.
2. Execute the `Worker(scriptURL)` constructor, and set the newly created
   `Worker` object's `integrity` attribute to `integrityMetadata`.
</section><!-- /Framework::JS::Workers::Worker -->
<section>
#### SharedWorker extension

attribute DOMString integrity
: The value of the SharedWorker's `integrity` attribute. Defaults to the empty string.
{:title="[Constructor (DOMString scriptURL, DOMString name, DOMString integrityMetadata)] partial interface Worker : EventTarget"}
{:.idl}

When the `SharedWorker(scriptURL, name, integrityMetadata)` constructor is
invoked:

1. If `integrityMetadata` is not a valid "named information" (`ni`) URL,
   throw a `SyntaxError` exception and abort these steps.
2. Execute the `SharedWorker(scriptURL, name)` constructor, and set the
   newly created `SharedWorker` object's `integrity` attribute to
   `integrityMetadata`.
</section><!-- /Framework::JS::Workers::SharedWorker -->

<section>
#### Validation

Add the following step directly after step 4 of the [run a worker][runworker]
algorithm:

5. If the script resource fetched in step 4 [does not match][match] the
   integrity metadata in the worker's `integrity` attribute, then for
   each `Worker` or `SharedWorker` object associated with <var>worker
   global scope</var>, [queue a task][] to [fire a simple event][] named
   `error` at that object. Abort these steps.
{:start="5"}
</section><!-- /Framework::JS::Workers::validation -->

</section><!-- /Framework::JS::Workers -->

<section>
#### XMLHttpRequest

To validate the integrity of resources loaded via `XMLHttpRequest`, a new
`integrity` attribute is added to the `XMLHttpRequest` object. If set, the
[integrity metadata][] in this attribute is used to validate the resource
before triggering the `load` event. [[!XMLHTTPREQUEST]]

<section>
##### The `integrity` attribute

The `integrity` attribute must return its value. Initially its value MUST
be the empty string.

Setting the `integrity` attribute MUST run these steps:

1. If the state is not `UNSENT` or `OPENED`, throw an `InvalidStateError`
   exception and abort these steps.
2. If the value provided is not a valid "named information" (`ni`) URL,
   throw a "SyntaxError` exception and abort these steps.
3. Set the `integrity` attribute's value to the value provided.

</section><!-- /Framework::JS::XHR::integrity -->

<section>
##### Validation

Whenever the user agent would [switch an `XMLHttpRequest` object to the
`DONE` state][switch-done], then perform the following steps before
switching state:

1.  If the `integrity` attribute is the empty string, or if the
    [response entity body][] [matches the value of the `integrity`
    attribute][match], then abort these steps, and continue to
    [switch to the `DONE` state][switch-done].
2.  Otherwise, [report a violation][], and run the following steps
    if the document's [integrity policy][] is `block`:
    1. Set the [response entity body][] to `null`
    2. Run the [request error][] steps for exception
       [`NetworkError`][xhrnetworkerror] and event [`error`][xhrerror].
    3. Do not continue to [switch to the `DONE` state][switch-done].

This validation only takes place when the entire resource body has been
downloaded. For that reason, developers who care about integrity validation
SHOULD ignore progress events fired while the resource is downloading, and
instead listen only for the `load` and `error` events. Data processed
before the `load` event fires is unvalidated, and potentially corrupt.

[switch-done]: https://dvcs.w3.org/hg/xhr/raw-file/tip/Overview.html#switch-done
[response entity body]: https://dvcs.w3.org/hg/xhr/raw-file/tip/Overview.html#response-entity-body
[request error]: http://www.w3.org/TR/XMLHttpRequest/#request-error
[xhrnetworkerror]: http://dev.w3.org/2006/webapi/DOM4Core/#networkerror
[xhrerror]: http://www.w3.org/TR/XMLHttpRequest/#event-xhr-error
</section><!-- Framework::JS::XHR::validation -->

</section><!-- /Framework::JS::XHR -->


</section><!-- /Framework::JS -->
</section><!-- /Framework -->

<section>
### Caching

JavaScript libraries are a good example of resources that are often loaded
and reloaded from different locations as users browse the web:
`http://cdnjs.cloudflare.com/ajax/libs/jquery/1.10.2/jquery.min.js` is
exactly the same file as
`https://ajax.googleapis.com/ajax/libs/jquery/1.10.2/jquery.min.js`. Both
files are identifiable via the `ni` URL
`ni:///sha-256;iaFenEC8axSAnyNu6M0-0epCOTwfbKVceFXNd5s_ki4`.

To reduce the performance impact of reloading the same data, user agents
MAY use [integrity metadata][] as a new index to a local cache, meaning that
a user who had already loaded a version of the file from `ajax.googleapis.com`
wouldn't have to touch the network to load the `cdnjs.cloudflare.com` version.
The user agent knows that the content is the same, and would be free to treat
the latter as a cache hit, regardless of the location mismatch.

<section>
#### Risks

This approach is good for performance, but can have security implications. See
the [origin confusion][] and [MIME type confusion][] sections below for some
details.

<section>
##### Origin confusion
[origin confusion]: #origin-confusion

User agents which set up a caching mechanism that uses only the integrity
metadata to identify a resource are vulnerable to attacks which bypass
same-origin restrictions unless they are very careful when choosing whether
or not to read data straight from the cache.

For instance:

* [Runtime script errors][onerror] are sanitized for resources that are
  [CORS-cross-origin][cors] to the page into which they are loaded. [[!HTML5]]

* XMLHttpRequest may only load data from same-origin resources, or from
  resources delivered with proper CORS headers. [[!XMLHTTPREQUEST]]

TODO: Moar.
{: .todo}

[onerror]: http://www.w3.org/TR/html5/webappapis.html#runtime-script-errors
[cors]: http://www.w3.org/TR/html5/infrastructure.html#cors-cross-origin
</section><!-- /Caching::Risks::Origin confusion -->

<section>
##### MIME type confusion
[MIME Type confusion]: #mime-type-confusion

User agents which set up a caching mechanism that uses only the integrity
metadata to identify a resource are vulnerable to attacks which create
resources that behave differently based on the context in which they are
loaded. [Gifar][] is the canonical example of such an attack.

Authors SHOULD mitigate this risk by specifing the expected content type
along with the digest, as specified in [RFC 6920, section 3.1][contenttype].
This means that the content type will be verified along with the digest when
determining whether a [resource matches certain integrity
metadata][match].

[Gifar]: http://en.wikipedia.org/wiki/Gifar
[contenttype]: http://tools.ietf.org/html/rfc6920#section-3.1
</section><!-- /Caching::Risks::MIME Type confusion -->
</section><!-- /Caching::Risks -->

<section>
#### Recommendations

To mitigate the risk of cross-origin data leakage or type-sniffing
exploitation, user agents that take this approach to caching MUST NOT
use [integrity metadata][] as a cache identifier unless the following
are all true:

*   The integrity metadata contains a content type.
*   The resource was delivered in response to an HTTP `GET` request (and not
    `POST`, `OPTIONS`, `TRACE`, etc.)
*   The resource was delivered with an `Access-Control-Allow-Origin` HTTP
    header with a value of `*` [[!CORS]]
*   The integrity metadata uses a hash function with very strong uniqueness
    characteristics: SHA-512 or better.

TODO: More ideas? Limiting to resources with wide-open CORS headers and strong
hash functions seems like a reasonable start...
{:.todo}
</section><!-- /Caching::Recommendations -->
</section><!-- /Caching -->

<section>
## Proxies

Optimizing proxies and other intermediate servers which modify the
content of fetched resources MUST ensure that the digest associated
with those resources stays in sync with the new content. One option
is to ensure that the [integrity metadata][] associated with
resources is updated along with the resource itself. Another
would be simply to deliver only the canonical version of resources
for which a page author has requested integrity verification. To
support this latter option, user agents MAY send an [HTTP Client
Hint][], as described below:

TODO: think about how integrity checks would effect `vary` headers
in general.
{:.todo}

<section>
### The `CH-Integrity` client hint

The `CH-Integrity` HTTP request header informs a server that a
resource will only be accepted if delivered in its canonical form:
in other words, the page author has placed a higher importance on
integrity than other considerations (filesize, performance, etc).

    "CH-Integrity:" integrity-value
    integrity-value = 1#( 1 / 0 )
    
A value of `1` means that the requested resource SHOULD be delivered
in its canonical form, without modification. A value of `0` means
that integrity checking is irrelevant to this fetch, and modifications
MAY be performed without violating integrity checks.
</section><!-- /Proxies::ClientHint -->

</section><!-- /Implementation -->

<section>
## Security Considerations

<section>
### Insecure channels remain insecure

[Integrity metadata][] delivered over an insecure channel provides no security
benefit. Attackers can alter the digest in-flight (or remove it entirely (or
do absolutely anything else to the document)), just as they could alter the
resource the hash is meant to validate. Authors who desire any sort of
security whatsoever SHOULD deliver resources containing digests over
secure channels.
</section><!-- /Security::Insecure channels -->

<section>
### Hash collision attacks

Digests are only as strong as the hash function used to generate them. User
agents SHOULD refuse to support known-weak hashing functions like MD5, and
SHOULD restrict supported hashing functions to those known to be
collision-resistant. At the time of writing, SHA-256 is a good baseline.
Moreover, user agents SHOULD reevaluate their supported hashing functions
on a regular basis, and deprecate support for those functions shown to be
insecure.
</section><!-- /Security::Hash collision -->

<section>
### Cross-origin data leakage

Attackers can determine whether some cross-origin resource has certain
content by attempting to load it with a known digest, and watching for
load failure. If the load fails, the attacker can surmise that the
resource didn't match the hash, and thereby gain some insight into its
contents. This might reveal, for example, whether or not a user is
logged into a particular service.

User agents SHOULD mitigate the risk by refusing to trigger `error`
handlers for cross-origin resources, but some side-channels will likely
be difficult to avoid (image's `naturalHeight`/`naturalWidth` for
instance).
</section><!-- /Security::cross-origin -->

</section><!-- /Security -->

<section>
## IANA Considerations

The permanent message header field registry (see [[!RFC3864]]) should be
updated with the following registration:

<section>
### `CH-Integrity`

Header field name
: CH-Integrity

Applicable protocol
: http

Status
: standard

Author/Change controller
: W3C

Specification document
: this specification (See [The `CH-Integrity` client hint][hint])

[hint]: #the-ch-integrity-client-hint
</section><!-- /IANA::CH-Integrity -->
</section><!-- /IANA -->

<section>
## Acknowledgements

None of this is new. Much of the content here is inspired heavily by Gervase
Markham's [Link Fingerprints][] concept, as well as WHATWG's [Link Hashes][].

[Link Fingerprints]: http://www.gerv.net/security/link-fingerprints/
[Link Hashes]: http://wiki.whatwg.org/wiki/Link_Hashes
</section>
