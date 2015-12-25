package WWW::OAuth::Authorizer::OAuth1_0;

use Class::Tiny::Chained qw(client_id client_secret token token_secret), {
	signature_method => 'HMAC-SHA1',
};

use Carp 'croak';
use Digest::SHA 'hmac_sha1';
use Encode 'encode';
use List::Util 'pairs', 'pairgrep';
use MIME::Base64 'encode_base64';
use Scalar::Util 'blessed';
use URI::Escape 'uri_escape';

use Role::Tiny::With;
with 'WWW::OAuth::Role::Authorizer';

our $VERSION = '0.001';

my %signature_methods = (
	'PLAINTEXT' => '_signature_plaintext',
	'HMAC-SHA1' => '_signature_hmac_sha1',
	'RSA-SHA1' => '_signature_rsa_sha1',
);

sub authorize_request {
	my ($self, $req) = @_;
	croak 'No request to authorize' unless defined $req;
	croak 'Request does not perform the role WWW::OAuth::HTTPRequest'
		unless blessed $req and $req->DOES('WWW::OAuth::HTTPRequest');
	
	my ($client_id, $client_secret, $token, $token_secret, $signature_method) =
		($self->client_id, $self->client_secret, $self->token, $self->token_secret, $self->signature_method);
	
	croak 'Client ID and secret are required to authorize'
		unless defined $client_id and defined $client_secret;
	
	$signature_method = 'RSA-SHA1' if blessed $signature_method and $signature_method->can('sign');
	my $sign = $signature_methods{$signature_method} // croak "Unknown signature method $signature_method";
	
	my %oauth_params = (
		oauth_consumer_key => $client_id,
		oauth_nonce => _nonce(),
		oauth_signature_method => $signature_method,
		oauth_timestamp => time,
		oauth_version => '1.0',
	);
	$oauth_params{oauth_token} = $token if defined $token;
	
	# All oauth parameters should be moved to the header
	my %body_oauth_params = pairgrep { $a =~ m/^oauth_/ } @{$req->body_pairs};
	if (%body_oauth_params) {
		%oauth_params = (%oauth_params, %body_oauth_params);
		$req->remove_body_params(keys %body_oauth_params);
	}
	
	# This parameter is not allowed when creating the signature
	delete $oauth_params{oauth_signature};
	
	$oauth_params{oauth_signature} = $self->$sign($req, \%oauth_params, $client_secret, $token_secret);
	
	my $auth_str = join ', ', map { $_ . '="' . uri_escape($oauth_params{$_}) . '"' } sort keys %oauth_params;
	$req->set_header("OAuth $auth_str");
	return $self;
}

sub _nonce {
	my $str = encode_base64 join('', map { chr int rand 256 } 1..24), '';
	$str =~ s/[^a-zA-Z0-9]//g;
	return $str;
}

sub _signature_plaintext {
	my ($self, $req, $oauth_params, $client_secret, $token_secret) = @_;
	return uri_escape($client_secret) . '&' . uri_escape($token_secret // '');
}

sub _signature_hmac_sha1 {
	my ($self, $req, $oauth_params, $client_secret, $token_secret) = @_;
	my $base_str = _signature_base_string($req, $oauth_params);
	my $signing_key = uri_escape($client_secret) . '&' . uri_escape($token_secret // '');
	return encode_base64(hmac_sha1($base_str, $signing_key), '');
}

sub _signature_rsa_sha1 {
	my ($self, $req, $oauth_params) = @_;
	my $base_str = _signature_base_string($req, $oauth_params);
	return $self->signature_method->sign($base_str);
}

sub _signature_base_string {
	my ($req, $oauth_params) = @_;
	
	my @encoded_params = map { uri_escape(encode('UTF-8', $_)) } (@{$req->query_pairs}, @{$req->body_pairs}, %$oauth_params);
	my @sorted_pairs = sort { ($a->[0] cmp $b->[0]) or ($a->[1] cmp $b->[1]) } pairs @encoded_params;
	my $params_str = join '&', map { $_->[0] . '=' . $_->[1] } @sorted_pairs;
	
	my $base_url = URI->new($req->url);
	$base_url->query(undef);
	$base_url->fragment(undef);
	return uc($req->method) . '&' . uri_escape($base_url) . '&' . uri_escape($params_str);
}

1;

=head1 NAME

WWW::OAuth::Authorizer::OAuth1_0 - Module abstract

=head1 SYNOPSIS

=head1 DESCRIPTION

=head1 BUGS

Report any issues on the public bugtracker.

=head1 AUTHOR

Dan Book <dbook@cpan.org>

=head1 COPYRIGHT AND LICENSE

This software is Copyright (c) 2015 by Dan Book.

This is free software, licensed under:

  The Artistic License 2.0 (GPL Compatible)

=head1 SEE ALSO
