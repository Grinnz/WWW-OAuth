package WWW::OAuth::Request::Mojo;

use strict;
use warnings;
use Class::Tiny::Chained 'request';

use Carp 'croak';
use Scalar::Util 'blessed';

use Role::Tiny::With;
with 'WWW::OAuth::Request';

our $VERSION = '0.001';

sub method { shift->request->method }

sub url {
	my $self = shift;
	return $self->request->url->to_string unless @_;
	$self->request->url->parse(shift);
	return $self;
}

sub content {
	my $self = shift;
	return $self->request->body unless @_;
	$self->request->body(shift);
	return $self;
}

sub content_is_form {
	my $self = shift;
	return 0 if $self->request->content->is_multipart;
	my $content_type = $self->request->headers->content_type || '';
	return 0 unless $content_type =~ m!application/x-www-form-urlencoded!i;
	return 1;
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

sub request_with {
	my ($self, $ua, $cb) = @_;
	croak 'Unknown user-agent object' unless blessed $ua and $ua->isa('Mojo::UserAgent');
	my $tx = $ua->build_tx($self->method, $self->url, $self->request->headers->to_hash, $self->content);
	return $ua->start($tx, $cb);
}

1;

=head1 NAME

WWW::OAuth::Request::Mojo - Module abstract

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
