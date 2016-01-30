package WWW::OAuth;

use strict;
use warnings;
use Class::Tiny::Chained qw(client_id client_secret token token_secret), {
	signature_method => 'HMAC-SHA1',
};

use Carp 'croak';
use Digest::SHA 'hmac_sha1';
use List::Util 'pairs', 'pairgrep';
use MIME::Base64 'encode_base64';
use Module::Runtime 'require_module';
use Role::Tiny ();
use Scalar::Util 'blessed';
use URI;
use URI::Escape 'uri_escape_utf8';

our $VERSION = '0.001';

sub request_from {
	my $self = shift;
	
	my ($class, %args);
	if (blessed $_[0]) { # Request object
		my $req = shift;
		if (Role::Tiny::does_role($req, 'WWW::OAuth::Request')) { # already in container
			return $req;
		} elsif ($req->isa('HTTP::Request')) {
			$class = 'HTTPRequest';
		} elsif ($req->isa('Mojo::Message')) {
			$class = 'Mojo';
		} else {
			$class = blessed $req;
			$class =~ s/:://g;
		}
		%args = (request => $req);
	} elsif (ref $_[0]) { # Hashref for HTTP::Tiny
		my $href = shift;
		$class = 'HTTPTiny';
		%args = %$href;
	} else { # Request class and args hashref
		($class, my $href) = @_;
		%args = %$href;
	}
	
	croak 'No request to authenticate' unless defined $class and %args;
	
	$class = "WWW::OAuth::Request::$class" unless $class =~ /::/;
	require_module $class;
	croak "Class $class does not perform the role WWW::OAuth::Request"
		unless Role::Tiny::does_role($class, 'WWW::OAuth::Request');
	
	return $class->new(%args);
}

my %signature_methods = (
	'PLAINTEXT' => '_signature_plaintext',
	'HMAC-SHA1' => '_signature_hmac_sha1',
	'RSA-SHA1' => '_signature_rsa_sha1',
);

sub authenticate {
	my $self = shift;
	my $req = $self->request_from(@_);
	
	my ($client_id, $client_secret, $token, $token_secret, $signature_method) =
		($self->client_id, $self->client_secret, $self->token, $self->token_secret, $self->signature_method);
	
	croak 'Client ID and secret are required to authenticate'
		unless defined $client_id and defined $client_secret;
	
	croak 'RSA-SHA1 signature method requires an object with a "sign" method' if $signature_method eq 'RSA-SHA1';
	$signature_method = 'RSA-SHA1' if blessed $signature_method and $signature_method->can('sign');
	my $sign = $signature_methods{$signature_method};
	croak "Unknown signature method $signature_method" unless defined $sign;
	
	my %oauth_params = (
		oauth_consumer_key => $client_id,
		oauth_nonce => _nonce(),
		oauth_signature_method => $signature_method,
		oauth_timestamp => time,
		oauth_version => '1.0',
	);
	$oauth_params{oauth_token} = $token if defined $token;
	
	# All oauth parameters should be moved to the header
	my %query_oauth_params = pairgrep { $a =~ m/^oauth_/ } @{$req->query_pairs};
	if (%query_oauth_params) {
		%oauth_params = (%oauth_params, %query_oauth_params);
		$req->remove_query_params(keys %query_oauth_params);
	}
	if ($req->body_is_form) {
		my %body_oauth_params = pairgrep { $a =~ m/^oauth_/ } @{$req->body_pairs};
		if (%body_oauth_params) {
			%oauth_params = (%oauth_params, %body_oauth_params);
			$req->remove_body_params(keys %body_oauth_params);
		}
	}
	
	# This parameter is not allowed when creating the signature
	delete $oauth_params{oauth_signature};
	
	$oauth_params{oauth_signature} = $self->$sign($req, \%oauth_params, $client_secret, $token_secret);
	
	my $auth_str = join ', ', map { $_ . '="' . uri_escape_utf8($oauth_params{$_}) . '"' } sort keys %oauth_params;
	$req->set_header(Authorization => "OAuth $auth_str");
	return $req;
}

sub _nonce {
	my $str = encode_base64 join('', map { chr int rand 256 } 1..32), '';
	$str =~ s/[^a-zA-Z0-9]//g;
	return $str;
}

sub _signature_plaintext {
	my ($self, $req, $oauth_params, $client_secret, $token_secret) = @_;
	$token_secret = '' unless defined $token_secret;
	return uri_escape_utf8($client_secret) . '&' . uri_escape_utf8($token_secret);
}

sub _signature_hmac_sha1 {
	my ($self, $req, $oauth_params, $client_secret, $token_secret) = @_;
	$token_secret = '' unless defined $token_secret;
	my $base_str = _signature_base_string($req, $oauth_params);
	my $signing_key = uri_escape_utf8($client_secret) . '&' . uri_escape_utf8($token_secret);
	return encode_base64(hmac_sha1($base_str, $signing_key), '');
}

sub _signature_rsa_sha1 {
	my ($self, $req, $oauth_params) = @_;
	my $base_str = _signature_base_string($req, $oauth_params);
	return $self->signature_method->sign($base_str);
}

sub _signature_base_string {
	my ($req, $oauth_params) = @_;
	
	my @encoded_params = map { uri_escape_utf8($_) } (@{$req->query_pairs}, %$oauth_params);
	push @encoded_params, map { uri_escape_utf8($_) } @{$req->body_pairs} if $req->body_is_form;
	my @sorted_pairs = sort { ($a->[0] cmp $b->[0]) or ($a->[1] cmp $b->[1]) } pairs @encoded_params;
	my $params_str = join '&', map { $_->[0] . '=' . $_->[1] } @sorted_pairs;
	
	my $base_url = URI->new($req->url);
	$base_url->query(undef);
	$base_url->fragment(undef);
	return uc($req->method) . '&' . uri_escape_utf8($base_url) . '&' . uri_escape_utf8($params_str);
}

1;

=head1 NAME

WWW::OAuth - Portable OAuth 1.0 authentication

=head1 SYNOPSIS

 use WWW::OAuth;
 
 my $oauth = WWW::OAuth->new(
   client_id => $client_id,
   client_secret => $client_secret,
   token => $token,
   token_secret => $token_secret,
 );
 
 # HTTP::Tiny
 use HTTP::Tiny;
 my $res = $oauth->authenticate(HTTPTiny => { method => 'GET', url => $url })
   ->request_with(HTTP::Tiny->new);
 
 # HTTP::Request
 use HTTP::Request::Common;
 use LWP::UserAgent;
 my $res = $oauth->authenticate(GET $url)->request_with(LWP::UserAgent->new);
 
 # Mojo::Message::Request
 use Mojo::UserAgent;
 my $tx = $ua->build_tx(get => $url);
 $tx = $oauth->authenticate($tx->req)->request_with(Mojo::UserAgent->new);
 
=head1 DESCRIPTION

L<WWW::OAuth> implements OAuth 1.0 request authentication according to
L<RFC 5849|http://tools.ietf.org/html/rfc5849>. It does not implement the user
agent requests needed for the complete OAuth 1.0 authorization flow; it only
prepares and signs requests, leaving the rest up to your application. It can
authenticate requests for L<LWP::UserAgent>, L<Mojo::UserAgent>, L<HTTP::Tiny>,
and can be extended to operate on other types of requests.

=head1 ATTRIBUTES

=head2 client_id

 my $client_id = $oauth->client_id;
 $oauth        = $oauth->client_id($client_id);

Client ID used to identify application (sometimes called an API key or consumer
key). Required for all requests.

=head2 client_secret

 my $client_secret = $oauth->client_secret;
 $oauth            = $oauth->client_secret($client_secret);

Client secret used to authenticate application (sometimes called an API secret
or consumer secret). Required for all requests.

=head2 token

 my $token = $oauth->token;
 $oauth    = $oauth->token($token);

Request or access token used to identify resource owner. Leave empty for
temporary credentials requests (request token requests).

=head2 token_secret

 my $token_secret = $oauth->token_secret;
 $oauth           = $oauth->token_secret($token_secret);

Request or access token secret used to authenticate on behalf of resource
owner. Leave empty for temporary credentials requests (request token requests).

=head2 signature_method

 my $method = $oauth->signature_method;
 $oauth     = $oauth->signature_method($method);

Signature method, can be C<PLAINTEXT>, C<HMAC-SHA1>, or an object that
implements the C<RSA-SHA1> method with a C<sign> method like
L<Crypt::OpenSSL::RSA>. Defaults to C<HMAC-SHA1>.

=head1 METHODS

=head2 request_from

 my $container = WWW::OAuth->request_from($http_request);
 my $container = WWW::OAuth->request_from(HTTPTiny => { method => 'GET', url => $url });

Can be called as a class or object method. Constructs an HTTP request container
performing the L<WWW::OAuth::Request> role. The input can either be a
recognized request object, or a container class name followed by a hashref of
constructor arguments. The class name will be appended to
C<WWW::OAuth::Request::> if it does not contain C<::>. Currently,
L<HTTP::Request> and L<Mojo::Message::Request> objects are recognized.

=head2 authenticate

 $container = $oauth->authenticate($container);
 my $container = $oauth->authenticate($http_request);
 my $container = $oauth->authenticate(HTTPTiny => { method => 'GET', url => $url });

Wraps the HTTP request in a container with L</"request_from">, then updates the
request URL, body, and headers as needed to construct and sign the request for
OAuth 1.0. Returns the container object.

=head1 HTTP REQUEST CONTAINERS

Request containers provide a unified interface for L</"authenticate"> to parse
and update HTTP requests. They must perform the L<Role::Tiny> role
L<WWW::OAuth::Request>. Custom container classes can be instantiated
directly or via L</"request_from">.

=head2 HTTPRequest

L<WWW::OAuth::Request::HTTPRequest> wraps a L<HTTP::Request> object, which
is compatible with several user agents including L<LWP::UserAgent>,
L<HTTP::Thin>, and L<Net::Async::HTTP>.

=head2 HTTPTiny

L<WWW::OAuth::Request::HTTPTiny> contains the request attributes directly,
as L<HTTP::Tiny> does not use request objects.

=head2 Mojo

L<WWW::OAuth::Request::Mojo> wraps a L<Mojo::Message::Request> object,
which is used by L<Mojo::UserAgent> via L<Mojo::Transaction>.

=head1 BUGS

Report any issues on the public bugtracker.

=head1 AUTHOR

Dan Book <dbook@cpan.org>

=head1 COPYRIGHT AND LICENSE

This software is Copyright (c) 2015 by Dan Book.

This is free software, licensed under:

  The Artistic License 2.0 (GPL Compatible)

=head1 SEE ALSO

L<Net::OAuth>, L<Mojolicious::Plugin::OAuth2>
