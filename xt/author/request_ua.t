use strict;
use warnings;
use Test::More;
use Test::Requires { 'Mojolicious' => '6.0' };

BEGIN {
	plan skip_all => 'Forking may be problematic on Windows' if $^O eq 'MSWin32';
}

use Mojolicious::Lite;
use Mojo::IOLoop;
use Mojo::IOLoop::Server;
use Mojo::Server::Daemon;
use Mojo::UserAgent;
use Module::Runtime 'use_module';
use WWW::OAuth::Util 'oauth_request';

my $port = Mojo::IOLoop::Server->generate_port;

my $pid = fork;
die "fork failed: $!" unless defined $pid;
unless ($pid) { # child
	my $guard = Mojo::IOLoop->timer(5 => sub { Mojo::IOLoop->stop });
	
	app->log->level('warn');
	
	get '/' => sub {
		my $c = shift;
		$c->render(text => 'foo');
	};
	
	get '/stop' => sub { Mojo::IOLoop->remove($guard); Mojo::IOLoop->stop };
	
	my $daemon = Mojo::Server::Daemon->new(listen => ["http://127.0.0.1:$port"], app => app);
	$daemon->run;
	
	exit;
}

sleep 0.25;

SKIP: {
	skip 'HTTP::Tiny is required to test basic requests', 2
		unless eval { use_module 'HTTP::Tiny' => '0.014'; 1 };
	my $req = oauth_request({method => 'GET', url => "http://127.0.0.1:$port"});
	my $res = $req->request_with(HTTP::Tiny->new);
	ok $res->{success}, 'request succeeded';
	is $res->{content}, 'foo', 'got response';
}

SKIP: {
	skip 'LWP::UserAgent and HTTP::Request are required to test HTTP::Request requests', 2
		unless eval { use_module $_ for 'LWP::UserAgent', 'HTTP::Request'; 1 };
	my $http_req = oauth_request(HTTP::Request->new(GET => "http://127.0.0.1:$port"));
	my $http_res = $http_req->request_with(LWP::UserAgent->new);
	ok $http_res->is_success, 'request succeeded';
	is $http_res->content, 'foo', 'got response';
}

my $ua = Mojo::UserAgent->new;
my $tx = $ua->build_tx(GET => "http://127.0.0.1:$port");
my $mojo_req = oauth_request($tx->req);
$tx = $mojo_req->request_with($ua);
ok $tx->success, 'request succeeded';
is $tx->res->body, 'foo', 'got response';

$ua->get("http://127.0.0.1:$port/stop");
waitpid $pid, 0;

done_testing;
