package WWW::OAuth::Request;

use List::Util 'pairgrep';
use URI;
use WWW::OAuth::Util 'form_urldecode', 'form_urlencode';

use Role::Tiny;

our $VERSION = '0.001';

requires 'method', 'url', 'content', 'content_is_form', 'set_header', 'request_with';

sub query_pairs { [URI->new(shift->url)->query_form] }

sub remove_query_params {
	my $self = shift;
	my %delete_names = map { ($_ => 1) } @_;
	my $url = URI->new($self->url);
	my @params = pairgrep { !exists $delete_names{$a} } $url->query_form;
	$url->query_form(\@params);
	$self->url("$url");
	return $self;
}

sub body_pairs {
	my $self = shift;
	return form_urldecode $self->content;
}

sub remove_body_params {
	my $self = shift;
	my %delete_names = map { ($_ => 1) } @_;
	my @params = pairgrep { !exists $delete_names{$a} } @{$self->body_pairs};
	$self->content(form_urlencode \@params);
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
