use strict;
use warnings;
use Test::More;
use Data::Section::Simple 'get_data_section';
use HTTP::Tiny;
use URI;
use URI::QueryParam;
use WWW::OAuth::Authorizer::OAuth1_0;
use WWW::OAuth::HTTPRequest::HTTPTiny;

my $api_key = $ENV{TWITTER_API_KEY};
my $api_secret = $ENV{TWITTER_API_SECRET};
my $oauth_base_url = 'https://api.twitter.com/oauth/';
my $api_base_url = 'https://api.twitter.com/1.1/';

my $test_online;
if ($ENV{AUTHOR_TESTING} and defined $api_key and defined $api_secret) {
	diag 'Running online test for Twitter OAuth 1.0';
	$test_online = 1;
} else {
	diag 'Running offline test for Twitter OAuth 1.0; set AUTHOR_TESTING and TWITTER_API_KEY/TWITTER_API_SECRET for online test';
	$api_key = 'foo';
	$api_secret = 'bar';
}

my $oauth_request_url = $oauth_base_url . 'request_token';
my $oauth_request = _request(POST => $oauth_request_url, { oauth_callback => 'oob' });
ok $oauth_request->body_is_form, 'OAuth request contains form body';
is $oauth_request->body, 'oauth_callback=oob', 'oauth parameter set in body';

my $auth = WWW::OAuth::Authorizer::OAuth1_0->new(client_id => $api_key, client_secret => $api_secret);
$auth->authorize_request($oauth_request);
is $oauth_request->body, '', 'oauth parameter removed from body';
is $oauth_request->url, $oauth_request_url, 'request url unchanged';

my $auth_header = $oauth_request->headers->{authorization} // '';
like $auth_header, qr/oauth_consumer_key/, 'oauth_consumer_key is set';
like $auth_header, qr/oauth_nonce/, 'oauth_nonce is set';
like $auth_header, qr/oauth_signature_method/, 'oauth_signature_method is set';
like $auth_header, qr/oauth_timestamp/, 'oauth_timestamp is set';
like $auth_header, qr/oauth_version/, 'oauth_version is set';
like $auth_header, qr/oauth_signature/, 'oauth_signature is set';
like $auth_header, qr/oauth_callback/, 'oauth_callback is set';



sub _request {
	my ($method, $url, $params) = @_;
	my $req = WWW::OAuth::HTTPRequest::HTTPTiny->new(method => $method, url => $url);
	if ($method eq 'GET' or $method eq 'HEAD') {
		my $uri = URI->new($url);
		$uri->query_form_hash($params);
		$req->url($uri->as_string);
	} else {
		$req->set_form($params);
	}
	return $req;
}

done_testing;

__DATA__


