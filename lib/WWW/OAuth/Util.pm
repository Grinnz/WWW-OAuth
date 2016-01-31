package WWW::OAuth::Util;

use Carp 'croak';
use Exporter 'import';
use List::Util 'pairs';
use Module::Runtime 'require_module';
use Role::Tiny ();
use Scalar::Util 'blessed';
use URI::Escape 'uri_escape_utf8', 'uri_unescape';

our $VERSION = '0.001';

our @EXPORT_OK = qw(form_urlencode form_urldecode oauth_request_from);

sub form_urlencode {
	my $form = shift;
	my @params;
	if (ref $form eq 'ARRAY') {
		@params = @$form;
	} elsif (ref $form eq 'HASH') {
		@params = %$form;
	} else {
		croak 'Form to urlencode must be hash or array reference';
	}
	croak 'Form to urlencode must be even-sized' if @params % 2;
	my @pairs;
	foreach my $pair (pairs @params) {
		my $key = $pair->[0];
		my @values = ref $pair->[1] eq 'ARRAY' ? @{$pair->[1]} : $pair->[1];
		do { s/ /+/g; $_ = uri_escape_utf8 $_ } for $key, @values;
		push @pairs, "$key=$_" for @values;
	}
	@pairs = sort @pairs if ref $form eq 'HASH';
	return join '&', @pairs;
}

sub form_urldecode {
	my $string = shift;
	my @form = map { $_ = '' unless defined $_; s/\+/ /g; $_ = uri_unescape $_; utf8::decode $_; $_ }
		map { my ($k, $v) = split /=/, $_, 2; ($k, $v) } split /&/, $string;
	return \@form;
}

sub oauth_request_from {
	my $class = ref $_[0] ? undef : shift;
	my $proto = shift;
	my %args;
	if (blessed $proto) { # Request object
		return $proto if Role::Tiny::does_role($proto, 'WWW::OAuth::Request'); # already in container
		if (!defined $class) {
			if ($proto->isa('HTTP::Request')) {
				$class = 'HTTP_Request';
			} elsif ($proto->isa('Mojo::Message')) {
				$class = 'Mojo';
			} else {
				$class = blessed $proto;
				$class =~ s/::/_/g;
			}
		}
		%args = (request => $req);
	} elsif (ref $proto eq 'HASH') { # Hashref
		$class = 'Basic' unless defined $class;
		%args = %$proto;
	} else {
		croak 'No request or request parameters found';
	}
	
	$class = "WWW::OAuth::Request::$class" unless $class =~ /::/;
	require_module $class;
	croak "Class $class does not perform the role WWW::OAuth::Request"
		unless Role::Tiny::does_role($class, 'WWW::OAuth::Request');
	
	return $class->new(%args);
}

1;

=head1 NAME

WWW::OAuth::Util - Utility functions for WWW::OAuth

=head1 SYNOPSIS

=head1 DESCRIPTION

=head1 FUNCTIONS

=head2 oauth_request_from

 my $container = oauth_request_from($http_request);
 my $container = oauth_request_from({ method => 'GET', url => $url });
 my $container = oauth_request_from(Basic => { method => 'POST', url => $url, content => $content });

Constructs an HTTP request container performing the L<WWW::OAuth::Request>
role. The input should be a recognized request object or hashref of arguments
optionally preceded by a container class name. The class name will be appended
to C<WWW::OAuth::Request::> if it does not contain C<::>. Currently,
L<HTTP::Request> and L<Mojo::Message::Request> objects are recognized, and
hashrefs will be used to construct a L<WWW::OAuth::Request::Basic> object if
no container class is specified.

 # Longer forms to construct WWW::OAuth::Request::HTTP_Request
 my $container = oauth_request_from(HTTP_Request => $http_request);
 my $container = oauth_request_from(HTTP_Request => { request => $http_request });

=head1 BUGS

Report any issues on the public bugtracker.

=head1 AUTHOR

Dan Book <dbook@cpan.org>

=head1 COPYRIGHT AND LICENSE

This software is Copyright (c) 2015 by Dan Book.

This is free software, licensed under:

  The Artistic License 2.0 (GPL Compatible)

=head1 SEE ALSO

L<HTTP::Request>, L<Mojo::Message::Request>
