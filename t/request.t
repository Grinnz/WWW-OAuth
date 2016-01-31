use strict;
use warnings;
use utf8;

{package WWW::OAuth::Request::Test;
	use Class::Tiny::Chained 'method', 'url', 'content';
	use Role::Tiny::With;
	with 'WWW::OAuth::Request';
	
	sub content_is_form { 1 }
	sub header { }
	sub request_with { }
}

use Test::More;
use WWW::OAuth::Util 'form_urlencode';

my $req = WWW::OAuth::Request::Test->new(url => 'http::example.com');
is_deeply $req->query_pairs, [], 'no query parameters';
is_deeply $req->body_pairs, [], 'no body parameters';

$req->url('http://example.com?' . form_urlencode [foo => ['☃', '❤'], '❤' => 'a b c', baz => 0]);
is_deeply $req->query_pairs, ['foo', '☃', 'foo', '❤', '❤', 'a b c', 'baz', '0'], 'URL has query parameters';

$req->remove_query_params('foo','❤');
is_deeply $req->query_pairs, ['baz', '0'], 'Query parameters were removed';

$req->content(form_urlencode [foo => ['☃', '❤'], '❤' => 'a b c', baz => 0]);
is_deeply $req->body_pairs, ['foo', '☃', 'foo', '❤', '❤', 'a b c', 'baz', '0'], 'Request has body parameters';

$req->remove_body_params('foo','❤');
is_deeply $req->body_pairs, ['baz', '0'], 'Body parameters were removed';

done_testing;