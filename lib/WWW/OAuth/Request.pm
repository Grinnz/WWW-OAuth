package WWW::OAuth::Request;

use Encode 'decode', 'encode';
use URI;
use URI::QueryParam;

use Role::Tiny;

our $VERSION = '0.001';

requires 'method', 'url', 'content', 'content_is_form', 'set_header', 'request_with';

sub query_pairs { [URI->new(shift->url)->query_form] }

sub remove_query_params {
	my $self = shift;
	my $url = URI->new($self->url);
	$url->query_param_delete($_) for @_;
	$self->url("$url");
	return $self;
}

sub body_pairs {
	my $self = shift;
	my $dummy = URI->new;
	$dummy->query($self->content);
	return [map { decode 'UTF-8', $_ } $dummy->query_form];
}

sub remove_body_params {
	my $self = shift;
	my $dummy = URI->new;
	$dummy->query($self->content);
	$dummy->query_param_delete(encode 'UTF-8', $_) for @_;
	my $content = $dummy->query;
	$self->content(defined $content ? $content : '');
	return $self;
}

1;

=head1 NAME

WWW::OAuth::Request - HTTP Request container role

=head1 SYNOPSIS

=head1 DESCRIPTION

=head1 METHODS

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