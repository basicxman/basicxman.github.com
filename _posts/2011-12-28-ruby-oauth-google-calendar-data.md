---
layout: post
title: OAuth Authentication with Ruby
tags:
  - oauth
  - google calendar
  - ruby
---

## OAuth Authentication with Ruby

### Overview

I have an <a href="https://github.com/basicxman/productivity-tracker" target="_blank">existing Rails application</a> which requires users to sync their data with Google Calendar.  I wanted to do this in a light-weight fashion and take the oppourtunity to learn OAuth consumption.  Google calendar currently uses <a href="http://oauth.net/core/1.0a/" target="_blank" title="Large Scary Protocol Reference">OAuth 1.0a</a>.

OAuth is a protocol which allows a user to give private data to a consumer without giving the consumer the credentials they would usually use in the provider's application.

### OAuth Workflow

We'll be using the 3-legged OAuth model which is quite common compared to the 2-legged model.  It consists of three basic steps for each user who wants to sync with Google Calendar.

* Get a <code>Request Token</code> from Google which will give Google information about our application (callback URL) and the purpose of this token (application scope).
* Authorize the <code>Request Token</code>. The user will enter their Google credentials and be sent back to your server at the specified callback URL.
* Level up the recently authorized <code>Request Token</code> to a proper <code>Access Token</code>. This token is used for actual API calls.

Each API hit and any steps in the OAuth workflow will require the request to be signed.  This involves encoding the parameters of the request and hashing it, followed by using a base64 encoding on the hash value.

### Dependencies

I used <a href="https://github.com/geemus/excon" target="_blank" title="Excon by geemus">Excon</a> for sending HTTPS requests and <a href="http://sinatrarb.com" target="_blank">Sinatra</a> to run a light weight web server as Google will need somewhere to send the user back to.

While Google Data supports JSON and XML, for this article we'll be using JSON.

A number of standard libaries are required to sign each request, including <code>openssl</code>, <code>digest/hmac</code> and <code>base64</code>.

{% highlight ruby %}
gem install sinatra
gem install excon
gem install json
{% endhighlight %}

### Google Calendar

To follow along, it is recommended that you <a href="https://accounts.google.com/ManageDomains" target="_blank">register a domain</a> with Google, this will give you a consumer key and secret value.  If you don't wish to do this, you can use the consumer and secret value <code>anonymous</code> as described in <a href="http://code.google.com/apis/accounts/docs/OAuth_ref.html#SigningOAuth" target="_blank">Google's documentation</a>.

Additional links to Google Calendar's documentation are available <a href="#RelevantLinks">below</a>.

### Writing the Client

Let's write a class to store some values such as the tokens and token secrets we'll receive along the way, as well as Google's OAuth endpoint URLs.

{% highlight ruby %}
require "sinatra"
require "excon"
require "cgi"
require "base64"
require "openssl"
require "digest/hmac"
require "json/pure"

class GoogleCalendar
  def initialize(key, secret, callback)
    @key      = key
    @secret   = secret
    @callback = callback

    @base_url = "https://www.google.com"
    @scope    = @base_url + "/calendar/feeds"
    @request_token_url    = "/accounts/OAuthGetRequestToken"
    @authorize_token_url  = "/accounts/OAuthAuthorizeToken"
    @access_token_url     = "/accounts/OAuthGetAccessToken"

    @feeds_url = @base_url + "/calendar/feeds/default/owncalendars/full"
  end
end

$calendar = GoogleCalendar.new("anonymous", "anonymous", "http://localhost:4567")
{% endhighlight %}

### Fetching a Request Token

Our first step in the OAuth workflow is to get our unauthorized <code>Request Token</code>.  We'll be writing a lot of scaffolding here which makes the rest of the requests quite easy.

The workflow is broken into two large portions, one section before the user is required to enter their credentials, and one afterwards.  As such, we'll define a method <code>execute_flow</code> to kick things off.

{% highlight ruby %}
def execute_flow
  get_request_token
  authorize_token
end
{% endhighlight %}

Let's start getting that initial request token.  The following method utilizes a bunch of helper methods that we'll look at later, but let's get straight to it for now.

{% highlight ruby linenos %}
def get_request_token
  url = @base_url + @request_token_url
  authentication, params = generate_authentication_hash({ :oauth_callback => @callback + "/oauth/authorize" }), { :scope => @scope }
  authentication.merge! oauth_signature(secret_string(@secret), :post, url, authentication, params)

  response = request(:post, url, normalize_parameters(params), { "Authorization" => authorization_string(authentication) })
  tokens = parse_tokens(response.body)
  @request_token  = tokens[:oauth_token]
  @request_secret = tokens[:oauth_token_secret]
end
{% endhighlight %}

#### Breakdown:

* Create our full URL for the request using the <code>Request Token</code> endpoint (line #2).
* Define a hash of parameters for the body of the request and the <code>Authorization</code> header (line #3).
* Add an <code>oauth_signature</code> parameter to the <code>authentication</code> hash, this contains the signature of our two hashes (line #4).
* Send a <code>POST</code> request to the endpoint with our parameters and <code>Authorization</code> header (line #6).
* Parse the resulting tokens (line #7).

Here's what our <code>params</code> hash and URL would look like.  The <code>authentication</code> will be looked at in detail <a href="#BacktotheRequestToken">below</a>.

{% highlight ruby %}
#=> 
{
  :scope=>"https://www.google.com/calendar/feeds"
}
#=> https://www.google.com/accounts/OAuthGetRequestToken
{% endhighlight %}

The <code>generate_authentication_hash</code> method is quite straightforward. It defines a hash of the required authorization parameters for all OAuth requests and then merges it with any additional sub-parameters.  For the <code>Request Token</code> we have an <code>oauth_callback</code> parameter which tells Google where to send the user after they've authorized our application.

The body contains a <code>scope</code> parameter which Google uses to control the level of access our application receives.  When the user authorizes this request token they'll be told exactly what they're authorizing.

<div class="center-content"><img src="/images/screenshots/oauth_authorization_scope.png" /></div>

<code>generate_authentication_hash</code> uses two other helper methods, <code>nonce</code> and <code>timestamp</code>.  <code>nonce</code> generates a <code>md5</code> hash value from a random number for the request.  <code>timestamp</code> returns a Unix timestamp.

> The nonce allows the Service Provider to verify that a request has never been made before and helps prevent replay attacks when requests are made over a non-secure channel (such as HTTP).

{% highlight ruby %}
def generate_authentication_hash(hash = {})
  {
    :oauth_consumer_key     => @key,
    :oauth_nonce            => nonce,
    :oauth_signature_method => "HMAC-SHA1",
    :oauth_timestamp        => timestamp,
    :oauth_version          => "1.0"
  }.merge(hash)
end

def nonce
  Digest::MD5.hexdigest(rand.to_s)
end

def timestamp
  Time.now.to_i.to_s
end
{% endhighlight %}

### Signing a Request

As mentioned, each request must have a signature containing a base64 encoded hash value from a string containing the normalized parameters.  Google offers two signature methods, <code>HMAC-SHA1</code> and <code>RSA-SHA1</code>.  The latter requires an <a href="http://code.google.com/apis/gdata/docs/auth/authsub.html#Registered" target="_blank">X.509 certificate</a> so we'll be using the former.  This former method uses a token secret and our consumer secret as the digest key.

The normalized parameters string consists of our URL encoded (<code>CGI.escape</code>) parameters within the request body or query string and the <code>Authorization</code> request header.  These normalized parameters are in query string format (<code>key=value&other_key=value</code>) and must be sorted by key with any duplicates sorted by value.

We split up our body parameters into the <code>params</code> hash and our <code>Authorization</code> parameters into the <code>authentication</code> hash.

Once we have our individually URL encoded, normalized parameters we can generate our signature base.  This is the data used in our digest.  The signature base consists of the HTTP verb (in this case for the <code>Request Token</code> we'll be using <code>POST</code>) concatenated with full URL of the request (protocol, hostname, and path, however no query parameters as these should be included in the normalized parameters set), followed by normalized parameters (URL encoded as a whole).  The substrings are joined together with ampersands as you can see in line #6.

{% highlight text %}
# Sample signature base.
GET&http%3A%2F%2Fwww.google.com%2Fcalendar%2Ffeeds%2Fdefault%2Fallcalendars%2Ffull&oauth_consumer_key%3Dexample.com%26oauth_nonce%3D4572616e48616d6d65724c61686176%26oauth_signature_method%3DRSA-SHA1%26oauth_timestamp%3D137131200%26oauth_token%3D1%252Fab3cd9j4ks73hf7g%26oauth_version%3D1.0%26orderby%3Dstarttime
{% endhighlight %}

{% highlight ruby linenos %}
def oauth_signature(secret, method, url, authentication, params = {})
  { :oauth_signature => sign(secret, generate_signature_base(method, url, normalize_parameters(authentication.merge(params)))) }
end

def generate_signature_base(method, url, param_string)
  [method.to_s.upcase, CGI.escape(url), CGI.escape(param_string)].join("&")
end

def sign(secret, string)
  Base64.encode64(OpenSSL::HMAC.digest("sha1", secret, string)).strip
end

def normalize_parameters(params)
  params.sort.inject("") { |str, (key, value)| str + "#{CGI.escape(key.to_s)}=#{CGI.escape(value)}&" }[0..-2]
end

def secret_string(secret, token_secret = "")
  "#{secret}&#{token_secret}"
end
{% endhighlight %}

The <code>oauth_signature</code> method accepts a <code>secret</code> parameter because the exact secret value we use will be different for each stage of the flow.  For the <code>Request Token</code> we shall merely use our consumer secret, however for future steps and API hits we'll be using that in accompaniment with a token secret.

Even in the situation of the <code>Request Token</code> where we only have our consumer secret, the value must still contain an ampersand (as the two values are usually joined with one).  Thus we have that final helper method <code>secret_string</code> (line #17).  Here's a sample secret string argument for a <code>Request Token</code>.

{% highlight text %}
anonymous&
{% endhighlight %}

While there are several ways to generate a <code>HMAC-SHA1</code> hash, <code>openssl</code> is the recommended, fastest way for modern Ruby applications.

If the signature is invalid, you'll get back an error in the response body such as the following.  Google is kind enough to show us the signature base it signed and compared to our signature.

{% highlight text %}
signature_invalid
base_string:POST&https%3A%2F%2Fwww.google.com%2Faccounts%2FOAuthGetRequestToken&oauth_callback%3Dhttp%253A%252F%252Flocalhost%253A4567%252Foauth%252Fauthorize%26oauth_consumer_key%3Danonymous%26oauth_nonce%3D53077bb6960f92b54969dd7bd5bd693d%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1319674839%26oauth_version%3D1.0%26scope%3Dhttps%253A%252F%252Fwww.google.com%252Fcalendar%252Ffeeds
{% endhighlight %}

### Back to the Request Token

Now that we can sign any of our requests, we can finally retrieve a <code>Request Token</code>.  I've written a helper method to send requests using <code>Excon</code>.  The helper method checks the HTTP verb we're using and if we're sending a <code>POST</code> request it will need the <code>Accept</code> and <code>Content-Type</code> headers.

{% highlight ruby %}
def request(method, url, body, headers = {})
  hash = if method == :post
    {
      "Accept" => "*/*",
      "Content-Type" => "application/x-www-form-urlencoded"
    }
  else
    {}
  end

  Excon.send(method, url, :body => body, :headers => hash.merge(headers)) # Hit that server yo.
end
{% endhighlight %}

Since the syntax of sending parameters in the <code>Authorization</code> header is different from the normalized parameters syntax, this will require one more helper method called <code>authorization_string</code>.  Given our authentication hash, this method will generate the correct value for the header.

With that in mind, we can send a request with the normalized <code>params</code> hash as the request's body and the <code>authentication</code> hash (now with the <code>oauth_signature</code> parameter) in the header.

{% highlight ruby %}
def authorization_string(params)
  "OAuth " + params.sort.map { |key, value| "#{key}=\"#{CGI.escape(value)}\"" }.join(", ")
end
{% endhighlight %}

Check out what our authorization string looks like with a sample <code>authentication</code> hash.

{% highlight ruby %}
{
  :oauth_consumer_key     => "anonymous",
  :oauth_nonce            => "68847fb8fc637a4f7f1e261b3fff98d0",
  :oauth_signature_method => "HMAC-SHA1",
  :oauth_timestamp        => "1319680960",
  :oauth_version          => "1.0",
  :oauth_callback         => "http://localhost:4567/oauth/authorize",
  :oauth_signature        => "Q/835qmyJVsoM68jR7uKeGtuxvc="
}

#=> OAuth oauth_callback="http%3A%2F%2Flocalhost%3A4567%2Foauth%2Fauthorize", oauth_consumer_key="anonymous", oauth_nonce="68847fb8fc637a4f7f1e261b3fff98d0", oauth_signature="Q%2F835qmyJVsoM68jR7uKeGtuxvc%3D", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1319680960", oauth_version="1.0"
{% endhighlight %}

Our HTTP request would be formed like so,

{% highlight text %}
POST /accounts/OAuthGetRequestToken HTTP/1.1
Host: www.google.com
Accept: */*
Content-Type: application/x-www-form-urlencoded
Authorization: OAuth oauth_callback="http%3A%2F%2Flocalhost%3A4567%2Foauth%2Fauthorize", oauth_consumer_key="anonymous", oauth_nonce="68847fb8fc637a4f7f1e261b3fff98d0", oauth_signature="Q%2F835qmyJVsoM68jR7uKeGtuxvc%3D", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1319680960", oauth_version="1.0"

scope=https%3A%2F%2Fwww.google.com%2Fcalendar%2Ffeeds%2Fdefault%2Fowncalendars%2Ffull
{% endhighlight %}

Once we have our response we can parse the resulting tokens from the response body.  The response from our <code>Request Token</code> endpoint will be a token and token secret (used for signing a future request).  A simple helper method can be used to parse this and we can assign the results to some instance variables.

A sample response body with the parameterized tokens looks like this,

{% highlight text %}
oauth_token=4%2F-ttt-GK7npEAAL3BNw9iTJfLMdOF&oauth_token_secret=v80_jAOfUm0IfX7itVRcsBhB&oauth_callback_confirmed=true
{% endhighlight %}

{% highlight ruby %}
def parse_tokens(string)
  string.split("&").inject({}) do |hash, pair|
    key, value = pair.split("=")
    hash.merge({ key.to_sym => CGI.unescape(value) })
  end
end
{% endhighlight %}

<b>Boom</b>.  We have our [unauthorized] request token.

### Authorize the Token

> "Gotta authourize that token mother fucker" - Samuel L. Jackson

Up to this point we have a token which Google knows about, and yet the user hasn't authorized it.  At this stage we need to send the user to the authorization endpoint.  This URL's query string will contain the unauthorized request token.

When we constructed our request token we specified a callback URL which means we need to be a running a server in our script.  Once the user has entered valid credentials to Google they'll be redirected to our callback URL containing an authorized request token!

The <code>authorize_token</code> method is quite simple, no more helper methods are required.  For the sake of convenience I have used a binary on OS X called <code>open</code> in order to open the user's browser.  In a real web application you'll have to redirect the user to the endpoint.

You can see in the following snippet that only three parameters are used.  Only <code>oauth_token</code> is required; the value should be the unauthorized request token from our previous request.  The other two parameters are for localization and the authenticating user's domain.

Since users can be a part of Google's services or their own businesses on Google Apps, the domain parameter can be important.  You can check out the docs on the <a href="http://code.google.com/apis/accounts/docs/OAuth_ref.html#GetAuth" target="_blank">authorization token endpoint</a> for more details.

{% highlight ruby %}
def authorize_token
  url = @base_url + @authorize_token_url + "?" + normalize_parameters({
    :oauth_token => @request_token,
    :hd => "default",
    :hl => "en"
  })
  `open "#{url}"`
end
{% endhighlight %}

The URL would look something like this given the previous examples,

{% highlight text %}
https://www.google.com/accounts/OAuthAuthorizeToken?hd=default&hl=en&oauth_token=4%2F-ttt-GK7npEAAL3BNw9iTJfLMdOF
{% endhighlight %}

This is starting to come together: user goes to page, user enters correct login credentials, user gets sent to callback.  Oh shit.  We need that aforementioned server.

{% highlight ruby %}
get "/oauth/authorize" do
  $calendar.from_authorization(params)
  redirect "/oauth/info"
end
{% endhighlight %}

You'll notice that after the <code>from_authorization</code> method is called the user gets redirected to a page on our server with the URL <code>/oauth/info</code>.  This will be for displaying all information and doing an API call once we have an access token.

Our <code>from_authorization</code> method will extract the token and verifier value (which the next request requires) and then call a shiny new method, <code>get_access_token</code>.  Hang in a little longer and we'll be hitting us some sweet Google Data APIs.

{% highlight ruby %}
def from_authorization(params)
  @authorized_request_token    = params["oauth_token"]
  @authorized_request_verifier = params["oauth_verifier"]
  get_access_token
end
{% endhighlight %}

### Level Up to an Access Token

> You should call Mario, 'cause you just got <<1-up'd.>>

The structure of the following <code>get_access_token</code> method is almost identical to our <code>get_request_token</code> method.

{% highlight ruby linenos %}
def get_access_token
  url = @base_url + @access_token_url

  authentication = generate_authentication_hash({
    :oauth_token    => @authorized_request_token,
    :oauth_verifier => @authorized_request_verifier
  })
  authentication.merge! oauth_signature(secret_string(@secret, @request_secret), :post, url, authentication)

  response = request(:post, url, "", { "Authorization" => authorization_string(authentication) })
  tokens = parse_tokens(response.body)
  @access_token  = tokens[:oauth_token]
  @access_secret = tokens[:oauth_token_secret]
end
{% endhighlight %}

#### Breakdown:

* Create our full URL for the request using the <code>Access Token</code> endpoint (line #2).
* Define a hash of parameters for the <code>Authorization</code> header, including the <code>oauth_token</code> and <code>oauth_verifier</code> parameters (line #4-7).
* Sign the hash as previously discussed (line #8).  Note the second argument passed to <code>secret_string</code>.
* Hit the server with a <code>POST</code> request (line #10).
* Parse the resulting access token and secret value (line #11)!
* The secret value will be used to sign all future API calls, which also use the token.

Our endpoint URL, authentication hash, authorization string, and secret string would look like the following.

{% highlight ruby %}
#=> https://www.google.com/accounts/OAuthGetAccessToken
#=>
{
  :oauth_consumer_key     => "anonymous",
  :oauth_nonce            => "c3c2acb1853b57a48203e9b806cd03d9",
  :oauth_signature_method => "HMAC-SHA1",
  :oauth_timestamp        => "1319681146",
  :oauth_version          => "1.0",
  :oauth_token            => "4/-ttt-GK7npEAAL3BNw9iTJfLMdOF",
  :oauth_verifier         => "HASB4pr_35JXSyZ2j4bNuSlo",
  :oauth_signature        => "VlPEBce3rxNFllz9lRkDCnxpizw="
}
#=>
OAuth oauth_consumer_key="anonymous", oauth_nonce="c3c2acb1853b57a48203e9b806cd03d9", oauth_signature="VlPEBce3rxNFllz9lRkDCnxpizw%3D", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1319681146", oauth_token="4%2F-ttt-GK7npEAAL3BNw9iTJfLMdOF", oauth_verifier="HASB4pr_35JXSyZ2j4bNuSlo", oauth_version="1.0"
#=> anonymous&v80_jAOfUm0IfX7itVRcsBhB
{% endhighlight %}


There's really nothing new to explain for this, our response body would look something like the following.

{% highlight text %}
oauth_token=1%2F6ovAi2lj0X8JuBpTkNvzWJl8gpeFCPpSEGSIbRzjcs0&oauth_token_secret=jOPRzPMWbt106HtOdL_3JQhm
{% endhighlight %}

We now have all required data to send API calls.

### Fireworks

Since we now have an access token, we can display all our data (for science of course) and do a couple sample API calls to demonstrate our new power.

From our callback we had redirected our user to <code>/oauth/info</code> so let's tell Sinatra about this route.

{% highlight ruby %}
get "/oauth/info" do
  <<-eof
  Request Token: #{$calendar.request_token}<br />
  Request Secret: #{$calendar.request_secret}<br />
  Authorized Request Token: #{$calendar.authorized_request_token}<br />
  Authorized Request Verifier: #{$calendar.authorized_request_verifier}<br />
  Access Token: #{$calendar.access_token}<br />
  Access Secret: #{$calendar.access_secret}<br />
  <br />
  #{$calendar.get_feeds}
  <br />
  <br />
  #{$calendar.create_calendar}
  eof
end
{% endhighlight %}

Some templating nerds just...nerdraged...at me for using a heredoc, but once again this is simply for science.

We'll need to add an <code>attr_accessor</code> statement so Sinatra can access those instance variables containing all our tokens and secrets from the <code>GoogleCalendar</code> instance.  Additionally you'll note we have two new methods, <code>get_feeds</code> and <code>create_calendar</code>.

{% highlight ruby %}
class GoogleCalendar
  attr_accessor :request_token, :request_secret, :authorized_request_token, :authorized_request_verifier, :access_token, :access_secret

  #...
  def get_feeds
    api_call(@feeds_url).body
  end

  def create_calendar
    data = {
      :title    => "Testing testing!",
      :details  => "The answer is 42.",
      :timeZone => "America/New_York",
      :hidden   => false,
      :color    => "#A32929",
      :location => "New York"
    }
    body = { :data => data }.to_json
    api_call(@feeds_url, :post, body).body
  end
  #...
end
{% endhighlight %}

The <code>get_feeds</code> method is quite straightforward, we call some fellow chap named <code>api_call</code> (creative name eh?) with our feeds URL.  By default this will be a <code>GET</code> request.

As for <code>create_calendar</code> you'll see that we have defined a hash with a bunch of data.  If you're clever you'll realize this is data for some new calendar.  The <code>api_call</code> call in this method shows us using the <code>POST</code> verb as well as some new body data (a JSON serialized hash).

Now the only thing left is to look at this fancy <code>api_call</code> method.

{% highlight ruby linenos %}
def api_call(url, method = :get, data = "")
  authentication, params = generate_authentication_hash({ :oauth_token => @access_token }), { :alt => "jsonc" }
  authentication.merge! oauth_signature(secret_string(@secret, @access_secret), method, url, authentication, params)

  headers = {
    "Authorization" => authorization_string(authentication),
    "GData-Version" => "2", # http://code.google.com/apis/calendar/data/2.0/developers_guide_protocol.html#Versioning
    "Accept" => "application/json"
  }
  headers["Content-Type"] = "application/json" if method == :post

  request(method, url + "?" + normalize_parameters(params), data, headers)
end
{% endhighlight %}

#### Breakdown:

* We're now using our access token as a sub parameter in the <code>Authorization</code> parameter (line #2).
* We have an <code>alt</code> parameter in our query string (later appended to the request URL) which tells Google we want to receive JSON (line #3).
* We're sending some extra headers here,
  * <code>GData-Version</code> is the version of the Google Data API (line #7).
  * <code>Accept</code> tells Google we're expecting JSON (line #8).
  * <code>Content-Type</code> is sent if we're using the <code>POST</code> verb (a create/update/delete action).  This notes we're sending JSON in the body (line #10).
* In the final line we go ahead and send the request, returning whichever response we get back.

### All done.

And we're all done!  In the future I'll likely be writing a post on integrating all this with a Rails application.

The completed code is available in the final section, however a link to it on GitHub is available below in the Relevant Links section.

### Relevant Links

* <a href="https://gist.github.com/1310680" target="_blank">Finished Ruby script on GitHub</a>
* <a href="http://code.google.com/apis/calendar/data/2.0/developers_guide_protocol.html" target="_blank">Google Calendar Version 2.0 Reference</a>
* <a href="http://code.google.com/apis/calendar/data/2.0/reference.html" target="_blank">Google Calendar Data API Reference</a>
* <a href="http://oauth.net/core/1.0a/" target="_blank">OAuth Core 1.0 Revision A Specification</a>
* <a href="https://github.com/geemus/excon" target="_blank">Excon on GitHub</a>
* <a href="http://www.sinatrarb.com/" target="_blank">Sinatra</a>
* <a href="http://ruby-doc.org/stdlib-1.9.2/libdoc/base64/rdoc/index.html" target="_blank">base64 Ruby stdlib</a>
* <a href="http://ruby-doc.org/stdlib-1.9.2/libdoc/cgi/rdoc/index.html" target="_blank">cgi Ruby stdlib</a>
* <a href="http://ruby-doc.org/stdlib-1.9.2/libdoc/openssl/rdoc/index.html" target="_blank">openssl Ruby stdlib</a>

### Completed Code

{% highlight ruby linenos %}
# Google Calendar access w/ Data API
# OAuth authentication.

require "sinatra"
require "excon"
require "cgi"
require "base64"
require "openssl"
require "digest/hmac"
require "json/pure"

class GoogleCalendar
  attr_accessor :request_token, :request_secret, :authorized_request_token, :authorized_request_verifier, :access_token, :access_secret

  def initialize(key, secret, callback)
    @key      = key
    @secret   = secret
    @callback = callback

    @base_url = "https://www.google.com"
    @scope    = @base_url + "/calendar/feeds"
    @request_token_url    = "/accounts/OAuthGetRequestToken"
    @authorize_token_url  = "/accounts/OAuthAuthorizeToken"
    @access_token_url     = "/accounts/OAuthGetAccessToken"

    @feeds_url = @base_url + "/calendar/feeds/default/owncalendars/full"
  end

  # Initial OAuth flow, get an unauthorized request token from Google and then
  # pass to the user for authorization.
  def execute_flow
    get_request_token
    authorize_token
  end

  # http://code.google.com/apis/calendar/data/2.0/developers_guide_protocol.html#RetrievingAllCalendars
  # Sample authorized GET request.
  def get_feeds
    api_call(@feeds_url).body
  end

  # http://code.google.com/apis/calendar/data/2.0/developers_guide_protocol.html#CreatingCalendars
  # Sample authorized POST request.
  def create_calendar
    data = {
      :title    => "Testing testing!",
      :details  => "The answer is 42.",
      :timeZone => "America/New_York",
      :hidden   => false,
      :color    => "#A32929",
      :location => "New York"
    }
    body = { :data => data }.to_json
    api_call(@feeds_url, :post, body).body
  end

  # User has authorized with Google and we have a token from the callback.
  def from_authorization(params)
    @authorized_request_token    = params["oauth_token"]
    @authorized_request_verifier = params["oauth_verifier"]
    get_access_token
  end

  private

  # Standard request for authorized API calls.
  def api_call(url, method = :get, data = "")
    authentication, params = generate_authentication_hash({ :oauth_token => @access_token }), { :alt => "jsonc" }
    authentication.merge! oauth_signature(secret_string(@secret, @access_secret), method, url, authentication, params)

    headers = {
      "Authorization" => authorization_string(authentication),
      "GData-Version" => "2", # http://code.google.com/apis/calendar/data/2.0/developers_guide_protocol.html#Versioning
      "Accept" => "application/json"
    }
    headers["Content-Type"] = "application/json" if method == :post

    request(method, url + "?" + normalize_parameters(params), data, headers)
  end

  # http://code.google.com/apis/accounts/docs/OAuth_ref.html#RequestToken
  def get_request_token
    url = @base_url + @request_token_url
    authentication, params = generate_authentication_hash({ :oauth_callback => @callback + "/oauth/authorize" }), { :scope => @scope }
    authentication.merge! oauth_signature(secret_string(@secret), :post, url, authentication, params)

    response = request(:post, url, normalize_parameters(params), { "Authorization" => authorization_string(authentication) })
    tokens = parse_tokens(response.body)
    @request_token  = tokens[:oauth_token]
    @request_secret = tokens[:oauth_token_secret]
  end

  # http://code.google.com/apis/accounts/docs/OAuth_ref.html#GetAuth
  def authorize_token
    url = @base_url + @authorize_token_url + "?" + normalize_parameters({
      :oauth_token => @request_token,
      :hd => "default",
      :hl => "en"
    })
    `open "#{url}"`
  end

  # http://code.google.com/apis/accounts/docs/OAuth_ref.html#AccessToken
  def get_access_token
    url = @base_url + @access_token_url

    authentication = generate_authentication_hash({
      :oauth_token    => @authorized_request_token,
      :oauth_verifier => @authorized_request_verifier
    })
    authentication.merge! oauth_signature(secret_string(@secret, @request_secret), :post, url, authentication)

    response = request(:post, url, "", { "Authorization" => authorization_string(authentication) })
    tokens = parse_tokens(response.body)
    @access_token  = tokens[:oauth_token]
    @access_secret = tokens[:oauth_token_secret]
  end

  # Even if the token secret is blank, the ampersand is required.
  # http://oauth.net/core/1.0/#rfc.section.9.2
  def secret_string(secret, token_secret = "")
    "#{secret}&#{token_secret}"
  end
  
  def request(method, url, body, headers = {})
    hash = if method == :post
      {
        "Accept" => "*/*",
        "Content-Type" => "application/x-www-form-urlencoded"
      }
    else
      {}
    end

    Excon.send(method, url, :body => body, :headers => hash.merge(headers)) # Hit that server yo.
  end

  def parse_tokens(string)
    string.split("&").inject({}) do |hash, pair|
      key, value = pair.split("=")
      hash.merge({ key.to_sym => CGI.unescape(value) })
    end
  end

  # Set of mandatory request-independent OAuth authentication parameters.
  def generate_authentication_hash(hash = {})
    {
      :oauth_consumer_key     => @key,
      :oauth_nonce            => nonce,
      :oauth_signature_method => "HMAC-SHA1",
      :oauth_timestamp        => timestamp,
      :oauth_version          => "1.0"
    }.merge(hash)
  end

  # Generate a signature parameter hash with a signed signature base.
  # http://code.google.com/apis/accounts/docs/OAuth_ref.html#SigningOAuth
  def oauth_signature(secret, method, url, authentication, params = {})
    { :oauth_signature => sign(secret, generate_signature_base(method, url, normalize_parameters(authentication.merge(params)))) }
  end

  # http://oauth.net/core/1.0/#rfc.section.9.1.3
  def generate_signature_base(method, url, param_string)
    [method.to_s.upcase, CGI.escape(url), CGI.escape(param_string)].join("&")
  end

  # Using the HMAC-SHA1 signature method.
  def sign(secret, string)
    Base64.encode64(OpenSSL::HMAC.digest("sha1", secret, string)).strip
  end

  # Generates string for the authorization header.
  def authorization_string(params)
    "OAuth " + params.sort.map { |key, value| "#{key}=\"#{CGI.escape(value)}\"" }.join(", ")
  end

  # Normalized parameters for signature or query string according to OAuth spec.
  # http://oauth.net/core/1.0/#rfc.section.9.1.1
  def normalize_parameters(params)
    params.sort.inject("") { |str, (key, value)| str + "#{CGI.escape(key.to_s)}=#{CGI.escape(value)}&" }[0..-2]
  end

  def nonce
    Digest::MD5.hexdigest(rand.to_s)
  end

  def timestamp
    Time.now.to_i.to_s
  end
end

get "/oauth/authorize" do
  $calendar.from_authorization(params)
  redirect "/oauth/info"
end

get "/oauth/info" do
  <<-eof
  Request Token: #{$calendar.request_token}<br />
  Request Secret: #{$calendar.request_secret}<br />
  Authorized Request Token: #{$calendar.authorized_request_token}<br />
  Authorized Request Verifier: #{$calendar.authorized_request_verifier}<br />
  Access Token: #{$calendar.access_token}<br />
  Access Secret: #{$calendar.access_secret}<br />
  <br />
  #{$calendar.get_feeds}
  <br />
  <br />
  #{$calendar.create_calendar}
  eof
end

$calendar = GoogleCalendar.new("anonymous", "anonymous", "http://localhost:4567")
$calendar.execute_flow
{% endhighlight %}
