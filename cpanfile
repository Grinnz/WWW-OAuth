requires 'perl' => '5.008001';
requires 'Carp';
requires 'Class::Tiny::Chained';
requires 'Digest::SHA';
requires 'List::Util' => '1.33';
requires 'MIME::Base64';
requires 'Module::Runtime';
requires 'Role::Tiny' => '2.000000';
requires 'Scalar::Util';
requires 'URI' => '1.28';
requires 'URI::Escape' => '3.26';
on test => sub {
	requires 'Data::Section::Simple';
	requires 'JSON::PP';
	requires 'Test::More' => '0.88';
	requires 'Test::Requires';
};
on develop => sub {
	recommends 'HTTP::Request';
	recommends 'HTTP::Tiny' => '0.014';
	recommends 'LWP::UserAgent';
	recommends 'Mojolicious' => '6.0';
};
