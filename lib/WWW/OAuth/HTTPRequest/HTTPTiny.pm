package WWW::OAuth::HTTPRequest::HTTPTiny;

use strict;
use warnings;
use Class::Tiny::Chained 'method', 'url', 'content', { headers => sub { {} } };

use Role::Tiny::With;
with 'WWW::OAuth::Role::HTTPTiny';

our $VERSION = '0.001';

sub body {
	my $self = shift;
	return $self->content unless @_;
	$self->content(shift);
	return $self;
}

sub body_is_form {
	my $self = shift;
	my $content_type = $self->headers->{'content-type'} || '';
	return 0 unless $content_type =~ m!application/x-www-form-urlencoded!i;
	return 1;
}

sub set_header { $_[0]->headers->{lc $_[1]} = $_[2]; $_[0] }

1;

=head1 NAME

WWW::OAuth::HTTPRequest::HTTPTiny - Module abstract

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
