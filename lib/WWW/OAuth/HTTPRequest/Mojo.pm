package WWW::OAuth::HTTPRequest::Mojo;

use Class::Tiny::Chained 'request';

use Role::Tiny::With;
with 'WWW::OAuth::Role::HTTPRequest';

our $VERSION = '0.001';

sub method { shift->request->method }

sub url {
	my $self = shift;
	return $self->request->url->to_string unless @_;
	$self->request->url->parse(shift);
	return $self;
}

sub body {
	my $self = shift;
	return $self->request->body unless @_;
	$self->request->body(shift);
	return $self;
}

sub query_pairs { shift->request->query_params->pairs }

sub remove_query_params {
	my $self = shift;
	my $params = $self->request->query_params;
	$params->remove($_) for @_;
	return $self;
}

sub body_pairs { shift->request->body_params->pairs }

sub remove_body_params {
	my $self = shift;
	my $params = $self->request->body_params;
	$params->remove($_) for @_;
	$self->request->body($params->to_string);
	return $self;
}

sub set_header { $_[0]->request->headers->header(@_[1,2]); $_[0] }

1;

=head1 NAME

WWW::OAuth::HTTPRequest::Mojo - Module abstract

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
