package WWW::OAuth::Request::Basic;

use strict;
use warnings;
use Class::Tiny::Chained 'method', 'url', 'content', { headers => sub { {} } };

use Carp 'croak';
use List::Util 'first';
use Scalar::Util 'blessed';

use Role::Tiny::With;
with 'WWW::OAuth::Request';

our $VERSION = '0.001';

sub content_is_form {
	my $self = shift;
	my $content_type_key = first { lc $_ eq 'content-type' } keys %{$self->headers};
	return 0 unless defined $content_type_key;
	my $content_type = $self->headers->{$content_type_key};
	return 0 unless defined $content_type and $content_type =~ m!application/x-www-form-urlencoded!i;
	return 1;
}

sub set_header { $_[0]->headers->{lc $_[1]} = $_[2]; $_[0] }

sub request_with {
	my ($self, $ua) = @_;
	croak 'Unknown user-agent object' unless blessed $ua and $ua->isa('HTTP::Tiny');
	return $ua->request($self->method, $self->url, { headers => $self->headers, content => $self->content });
}

1;

=head1 NAME

WWW::OAuth::Request::Basic - Module abstract

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
