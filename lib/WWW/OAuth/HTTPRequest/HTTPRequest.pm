package WWW::OAuth::HTTPRequest::HTTPRequest;

use Class::Tiny::Chained 'request';
use URI::QueryParam;

use Role::Tiny::With;
with 'WWW::OAuth::Role::HTTPRequest';

our $VERSION = '0.001';

sub method { shift->request->method }

sub url {
	my $self = shift;
	return $self->request->uri->as_string unless @_;
	$self->request->uri(shift);
	return $self;
}

sub body {
	my $self = shift;
	return $self->request->content unless @_;
	$self->request->content(shift);
	return $self;
}

sub query_pairs { [shift->request->uri->query_form] }

sub remove_query_params {
	my $self = shift;
	my $uri = $self->request->uri;
	$uri->query_param_delete($_) for @_;
	return $self;
}

sub set_header { $_[0]->request->header(@_[1,2]); $_[0] }

1;

=head1 NAME

WWW::OAuth::HTTPRequest::HTTPRequest - Module abstract

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
