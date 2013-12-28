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
canonical, rendered or executed, and cached. Users are left open to a number
of attack vectors that might change the content of resources in such a way
as to produce something maliciously different from the author's intent. DNS
poisoning, man-in-the-middle, and so on are examples that are regularly seen
in the wild.

We can mitigate the risk of these kinds of attacks by allowing authors to
more clearly explain to the user agent _exactly_ which resource they intend
to load. If an author can provide integrity metadata above and beyond the
bare URL, then the user agent can validate that the data fetched from the
URL provied actually matches the authors' intent.

This document specifies such a validation scheme, extending several HTML
elements with a `digest` attribute that contains a cryptographic hash of
the contents of the resource the author expects to load. For instance, an
author may wish to load jQuery from a shared server rather than hosting it
on their own origin. Specifying that the _expected_ SHA-256 hash of
[`https://code.jquery.com/jquery-1.10.2.min.js`][1]
is `C6CB9UYIS9UJeqinPHWTHVqh_E1uhG5Twh-Y5qFQmYg` means
that the user agent can verify that the data it loads from that URL matches
that expected hash before executing the JavaScript it contains. This
integrity verification significantly reduces the risk that an active
network attacker can substitute malicious content.

The mechanism specified here may also be useful for purposes other than
validation. User agents may decide to use digests as identifiers in a
local cache, for instance, meaning that common resources could be cached
cross-origin.

[1]: curl https://code.jquery.com/jquery-1.10.2.min.js
</section>

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

A <dfn>base64url encoding</dfn> is defined in
[RFC 4648, section 5][base64url]. In a nutshell, it replaces the characters
U+002B PLUS SIGN (`+`) and U+002F SOLIDUS (`/`) characters in normal base64
encoding with the U+002D HYPHEN-MINUS (`-`) and U+005F LOW LINE (`_`)
characters, respectively. [[!RFC4648]]

[base64url]: http://tools.ietf.org/html/rfc4648#section-5

The Augmented Backus-Naur Form (ABNF) notation used in this document is
specified in RFC 5234. [[!ABNF]]

The following core rules are included by reference, as defined in
the [ABNF Appendix B.1][abnf-b1]: `ALPHA` (letters), `DIGIT` (decimal 0-9), `WSP`
(white space) and `VCHAR` (printing characters).

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
risk of certain attack vectors (see [MIME Type confusion][security-mime] in
this document's Security Considerations section).

[security-mime]: #mime-type-confusion

This metadata is generally encoded as a "named information" (`ni`) URI, as defined in RFC6920. [[!RFC6920]]

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

[sha2]: #def-sha-2
[digest]: #def-digest
</section><!-- /Framework::Required metadata -->

<section>
### Resource verification algorithms

<section>
#### Apply <var>algorithm</var> to <var>resource</var>

1. If <var>algorithm</var> is not a hash function recognized and supported
   by the user agent, return `null`.
2. Let <var>result</var> be the result of applying <var>algorithm</var> to
   <var>resource</var>.
3. Let <var>encodedResult</var> be result of base64url-encoding
   <var>result</var>.
4. Strip any trailing U+003D EQUALS SIGN (`=`) characters from
   <var>encodedResult</var>.
5. Return <var>encodedResult</var>.

[apply-algorithm]: #apply-algorithm-to-resource
</section>
<section>
#### Does <var>resource</var> match <var>digest</var>?

1. If <var>digest</var> is the empty string, return `true`.
2. If <var>digest</var> is not a valid "named information" (`ni`) URI,
   return `false`.
3. Let <var>algorithm</var> be the <var>alg</var> component of
   <var>digest</var>.
4. Let <var>expectedValue</var> be the <var>val</var> component of
   <var>digest</var>.
5. Let <var>actualValue</var> be the result of [applying
   <var>algorithm</var> to <var>resource</var>][apply-algorithm].
6. If <var>actualValue</var> is `null`, return `false`.
7. If <var>actualValue</var> is a case-sensitive match for
   <var>expectedValue</var>, return `true`. Otherwise, return `false`.

[match]: #does-resource-match-digest
</section>
</section>

<section>
### Verification of HTML document subresources

A variety of HTML elements result in requests for resources that are to be
embedded into the document, or executed in its context. To support integrity
metadata for each of these, and new elements that are added in the future,
a new `digest` attribute is added to HTML5's list of
[global attributes][global] that MAY be specified on any HTML element, and
a corresponding attribute is added to the [<code>HTMLElement</code>
interface][htmlelement].

[global]: http://www.w3.org/TR/html5/dom.html#global-attributes
[htmlelement]: http://www.w3.org/TR/html5/dom.html#htmlelement

<section>
#### The `digest` attribute

The `digest` attribute represents integrity metadata for an element. The
value of the attribute MUST be either the empty string, or a valid "named
information" (`ni`) URI. [[!RFC6920]]

The `digest` IDL attribute must [reflect][] the `digest` content attribute.

[reflect]: http://www.w3.org/TR/html5/infrastructure.html#reflect
</section><!-- /Framework::HTML::digest -->

<section>
#### HTMLElement extension

attribute DOMString digest
: The value of this element's `digest` attribute
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
render or execute resources that fail an integrity check, <em>and</em> must 
[report a violation][].

If the document's integrity policy is `report`, the user agent MAY refuse to
render or execute resources that fail an integrity check, <em>and</em> MUST 
[report a violation][].

If the document's integrity policy is `fallback`, the user agent MUST
[report a violation][], and MAY load a fallback resource via a TODO
mechansism that isn't specified yet.
{:.todo}

[csp]: http://w3.org/TR/CSP11
[report a violation]: http://www.w3.org/TR/CSP11/#dfn-report-a-violation
[integrity policy]: #dfn-integrity-policy
</section>

<section>
##### Elements

<section>
###### The `script` element

Insert the following steps after step 5 of step 14 of HTML5's
["prepare a script" algorithm][prepare]:

6.  Let <var>digest</var> be the value of the element's `digest` attribute.
7.  If <var>digest</var> is the empty string, skip the remaining steps.
8.  Once the [fetching algorithm][] has completed:
    1.  Let <var>resource</var> be the binary representation of the body of
        the response returned from the fetching algorithm.
    2.  If [resource does not match <var>digest</var>][match]:
        1.  If the document's [integrity policy][] is `block`, [queue a
            task][queue] to [fire a simple event][fire-simple] named `error`
            at the element, and abort these steps.
        2.  If the document's [integrity policy][] is `fallback`...
{:start="6"}

TODO: It's not clear that "binary representation of the body ..."
does what we want. I don't think we yet have a good way of saying "bits
on the wire".
{:.todo}

[prepare]: http://www.w3.org/TR/html5/scripting-1.html#prepare-a-script
[fetching algorithm]: http://www.w3.org/TR/html5/infrastructure.html#fetch
[queue]: http://www.w3.org/TR/html5/webappapis.html#queue-a-task
[fire-simple]: http://www.w3.org/TR/html5/webappapis.html#fire-a-simple-event
</section><!-- /Framework::HTML::Elements::script -->

<section>
###### The `every-other` element

<div class="todo">
TODO: `script` is a good stard, but at a minimum, we'll need to cover the
following set of elements:

* audio
* embed
* iframe
* img
* link
* object
* source
* video
</div>
</section><!-- /Framework::HTML::Elements::* -->

</section><!-- /Framework::HTML::Elements -->

</section><!-- /Framework::HTML -->
</section><!-- /Framework -->

<section>
## Security Considerations

<section>
### Insecure channels remain insecure

A digest delivered over an insecure channel provides no security benefit.
Attackers can alter the digest in-flight (or remove it entirely (or do
absolutely anything else to the document)), just as they could alter the
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
### Origin confusion

User agents which set up a caching mechanism that uses only the digest to
identify a resource are vulnerable to attacks which bypass same-origin
restrictions unless they are very careful when choosing whether or not to
read data straight from the cache.

For instance:

* [Runtime script errors][onerror] are sanitized for resources that are
  [CORS-cross-origin][cors] to the page into which they are loaded. [[!HTML5]]

* XMLHttpRequest may only load data from same-origin resources, or from
  resources delivered with proper CORS headers. [[!XMLHTTPREQUEST]]

TODO: Moar.
{: .todo}

[onerror]: http://www.w3.org/TR/html5/webappapis.html#runtime-script-errors
[cors]: http://www.w3.org/TR/html5/infrastructure.html#cors-cross-origin
</section><!-- /Security::Origin confusion -->

<section>
### MIME type confusion

User agents which set up a caching mechanism that uses only the digest to
identify a resource are vulnerable to attacks which create resources that
behave differently based on the context in which they are loaded. [Gifar][]
is the canonical example of such an attack.

Authors SHOULD mitigate this risk by specifing the expected content type
along with the digest, as specified in [RFC 6920, section 3.1][contenttype],
and verifying that the content type of the resource matches the expectations
of the context into which it is loaded. For instance, a resource of type
`text/plain` loaded via a `script` element MUST not execute.

[Gifar]: http://en.wikipedia.org/wiki/Gifar
[contenttype]: http://tools.ietf.org/html/rfc6920#section-3.1
</section><!-- /Security::MIME Type confusion -->

</section><!-- /Security -->
