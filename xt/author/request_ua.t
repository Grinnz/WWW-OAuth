use strict;
use warnings;
use Test::More;
use Module::Runtime 'require_module';
use WWW::OAuth::Util 'oauth_request';

BEGIN {
	plan skip_all => 'Forking may be problematic on Windows' if $^O eq 'MSWin32';
	my @mojo_modules = qw(Mojolicious::Lite Mojo::IOLoop Mojo::IOLoop::Server Mojo::Server::Daemon Mojo::UserAgent);
	plan skip_all => 'Mojolicious is required to test requests'
		unless eval { require_module $_ for @mojo_modules; 1 };
	plan skip_all => 'HTTP::Tiny is required to test requests'
		unless eval { require_module 'HTTP::Tiny'; 1 };
	plan skip_all => 'LWP::UserAgent is required to test requests'
		unless eval { require_module $_ for 'LWP::UserAgent', 'HTTP::Request'; 1 };
	Mojolicious::Lite->import;
}

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

my $req = oauth_request({method => 'GET', url => "http://127.0.0.1:$port"});
my $res = $req->request_with(HTTP::Tiny->new);
ok $res->{success}, 'request succeeded';
is $res->{content}, 'foo', 'got response';

my $http_req = oauth_request(HTTP::Request->new(GET => "http://127.0.0.1:$port"));
my $http_res = $http_req->request_with(LWP::UserAgent->new);
ok $http_res->is_success, 'request succeeded';
is $http_res->content, 'foo', 'got response';

my $ua = Mojo::UserAgent->new;
my $tx = $ua->build_tx(GET => "http://127.0.0.1:$port");
my $mojo_req = oauth_request($tx->req);
$tx = $mojo_req->request_with($ua);
ok $tx->success, 'request succeeded';
is $tx->res->body, 'foo', 'got response';

$ua->get("http://127.0.0.1:$port/stop");
waitpid $pid, 0;

done_testing;