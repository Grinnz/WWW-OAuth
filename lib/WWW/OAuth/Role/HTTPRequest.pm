package WWW::OAuth::Role::HTTPRequest;

use Encode 'decode', 'encode';
use URI;
use URI::QueryParam;

use Role::Tiny;

our $VERSION = '0.001';

requires 'method', 'url', 'body', 'body_is_form', 'set_header';

sub query_pairs { [URI->new(shift->url)->query_form] }

sub remove_query_params {
	my $self = shift;
	my $url = URI->new($self->url);
	$url->query_param_delete($_) for @_;
	$self->url($url);
	return $self;
}

sub body_pairs {
	my $self = shift;
	my $dummy = URI->new;
	$dummy->query($self->body);
	return [map { decode 'UTF-8', $_ } $dummy->query_form];
}

sub remove_body_params {
	my $self = shift;
	my $dummy = URI->new;
	$dummy->query($self->body);
	$dummy->query_param_delete(encode 'UTF-8', $_) for @_;
	my $body = $dummy->query;
	$body = '' unless defined $body;
	$self->body($body);
	return $self;
}

1;

=head1 NAME

WWW::OAuth::Role::HTTPRequest - Module abstract

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
