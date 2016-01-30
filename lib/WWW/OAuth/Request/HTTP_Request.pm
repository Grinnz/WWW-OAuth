package WWW::OAuth::Request::HTTP_Request;

use strict;
use warnings;
use Class::Tiny::Chained 'request';

use Carp 'croak';
use Scalar::Util 'blessed';
use URI::QueryParam;

use Role::Tiny::With;
with 'WWW::OAuth::Request';

our $VERSION = '0.001';

sub method { shift->request->method }

sub url {
	my $self = shift;
	return $self->request->uri->as_string unless @_;
	$self->request->uri(shift);
	return $self;
}

sub content {
	my $self = shift;
	return $self->request->content unless @_;
	$self->request->content(shift);
	return $self;
}

sub content_is_form {
	my $self = shift;
	my @parts = $self->request->parts;
	return 0 if @parts;
	my $content_type = $self->request->headers->content_type || '';
	return 0 unless $content_type =~ m!application/x-www-form-urlencoded!i;
	return 1;
}

sub query_pairs { [shift->request->uri->query_form] }

sub remove_query_params {
	my $self = shift;
	my $uri = $self->request->uri;
	$uri->query_param_delete($_) for @_;
	return $self;
}

sub set_header { $_[0]->request->header(@_[1,2]); $_[0] }

sub request_with {
	my ($self, $ua) = @_;
	croak 'Invalid user-agent object' unless blessed $ua;
	if ($ua->isa('LWP::UserAgent')) {
		return $ua->request($self->request);
	} elsif ($ua->isa('Net::Async::HTTP')) {
		return $ua->do_request(request => $self->request);
	} else {
		my $class = blessed $ua;
		croak "Unknown user-agent class $class";
	}
}

1;

=head1 NAME

WWW::OAuth::Request::HTTP_Request - Module abstract

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
