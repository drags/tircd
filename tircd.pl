#!/usr/bin/perl
# tircd - An ircd proxy to the Twitter API
# Copyright (c) 2009 Chris Nelson <tircd@crazybrain.org>
# Copyright (c) 2010-2011 Tim Sogard <tircd@timsogard.com>
# tircd is free software; you can redistribute it and/or modify it under the terms of either:
# a) the GNU General Public License as published by the Free Software Foundation
# b) the "Artistic License"

use strict;
use JSON::Any;
use Net::Twitter::Lite::WithAPIv1_1 0.12000;
use Time::Local;
use File::Glob ':glob';
use IO::File;
use LWP::UserAgent;
use Storable;
use POE qw(Component::Server::TCP Filter::Stackable Filter::Map Filter::IRCD);
use URI qw/host/;
use List::Util 'shuffle';
# @Olatho - issue 45
use HTML::Entities;

use Digest::SHA1  qw(sha1_base64);


my $VERSION = 2011082301;

# consumer key/secret in the executable instead of config because it should not be edited by user
my $tw_oauth_con_key = "4AQca4GFiWWaifUknq35Q";
my $tw_oauth_con_sec = "VB0exmHlErkx4GUUsXvoR4bqaXi56Rl43NL1Z9Q";

# I have no idea what the minimum Net::Twitter::Lite version is
#Do some sanity checks on the environment and warn if not what we want
#if ($Net::Twitter::Lite::VERSION < 2.10) {
#  print "Warning: Your system has an old version of Net::Twitter::Lite.  Please upgrade to the current version.\n";
#}

my $j = JSON::Any->new;
if ($j->handlerType eq 'JSON::Syck') {
  print "Warning: Your system is using JSON::Syck. This will cause problems with character encoding.   Please install JSON::PP or JSON::XS.\n";
}

#load and parse our own very simple config file
#didn't want to introduce another module requirement to parse XML or a YAML file
my $config_file = '/etc/tircd.cfg';
if ($ARGV[0]) {
  $config_file = $ARGV[0];
} elsif (-e 'tircd.cfg') {
  $config_file = 'tircd.cfg';
} elsif (-e bsd_glob('~',GLOB_TILDE | GLOB_ERR).'/.tircd') {
  $config_file = bsd_glob('~',GLOB_TILDE | GLOB_ERR).'/.tircd';
}

open(C,$config_file) || die("$0: Unable to load config file ($config_file): $!\n");
my %config = ();
while (<C>) {
  chomp;
  next if /^#/ || /^$/;
  my ($key,$value) = split(/\s/,$_,2);
  $config{$key} = $value;
}
close(C);

#config file backwards compatibility
$config{'timeline_count'} = 20 if !exists $config{'timeline_count'};
$config{'storage_path'} =~ s/~/$ENV{'HOME'}/ if ($config{'storage_path'} =~ /~/);

#storage for connected users
my %users;

#setup our filter to process the IRC messages, jacked from the Filter::IRCD docs
my $filter = POE::Filter::Stackable->new();
$filter->push( POE::Filter::Line->new( InputRegexp => '\015?\012', OutputLiteral => "\015\012" ));
#twitter's json feed escapes < and >, let's fix that
$filter->push( POE::Filter::Map->new(Code => sub {
  local $_ = shift;
  # @Olatho - Issue 45 - see also issue 50
  decode_entities($_);
  return $_;
}));
if ($config{'debug'} > 1) {
  $filter->push(POE::Filter::IRCD->new(debug => 1));
} else {
  $filter->push(POE::Filter::IRCD->new(debug => 0));
}

# if configured to use SSL, and no env vars yet defined, set to config settings
if ($config{'use_ssl'} == 1 && !($ENV{'HTTPS_CA_FILE'} || $ENV{'HTTPS_CA_DIR'})) {
	if ($config{'https_ca_file'} and -e $config{'https_ca_file'}) {
		$ENV{'HTTPS_CA_FILE'} = $config{'https_ca_file'};
	} elsif ($config{'https_ca_dir'} && -d $config{'https_ca_dir'}) {
		$ENV{'HTTPS_CA_DIR'} = $config{'https_ca_dir'};
	}
}

#if needed setup our logging sesstion
if ($config{'logtype'} ne 'none') {
  POE::Session->create(
      inline_states => {
        _start => \&logger_setup,
        log => \&logger_log
      },
      args => [$config{'logtype'},$config{'logfile'}]
  );
}

#setup our 'irc server'
POE::Component::Server::TCP->new(
  Alias			=> "tircd",              
  Address		=> $config{'address'},
  Port			=> $config{'port'},
  InlineStates		=> { 
    PASS => \&irc_pass, 
    NICK => \&irc_nick, 
    USER => \&irc_user,
    MOTD => \&irc_motd, 
    MODE => \&irc_mode, 
    JOIN => \&irc_join,
    PART => \&irc_part,
    WHO  => \&irc_who,
    WHOIS => \&irc_whois,
    PRIVMSG => \&irc_privmsg,
    STATS => \&irc_stats,
    INVITE => \&irc_invite,
    KICK => \&irc_kick,
    QUIT => \&irc_quit,
    PING => \&irc_ping,
    AWAY => \&irc_away,
    TOPIC => \&irc_topic,

    '#twitter' => \&channel_twitter,
    
    server_reply => \&irc_reply,
    user_msg	 => \&irc_user_msg,
    handle_command => \&irc_twitterbot_command,

    twitter_post_tweet => \&twitter_post_tweet,
    twitter_retweet_tweet => \&twitter_retweet_tweet,
    twitter_reply_to_tweet => \&twitter_reply_to_tweet,
    twitter_send_dm => \&twitter_send_dm,
    twitter_conversation => \&twitter_conversation,
    twitter_conversation_r => \&twitter_conversation_r,
    twitter_conversation_related => \&twitter_conversation_related,
    twitter_api_error => \&twitter_api_error,    
    twitter_timeline => \&twitter_timeline,
    twitter_direct_messages => \&twitter_direct_messages,
    twitter_search => \&twitter_search,
    
    login => \&tircd_login,
    getfriend => \&tircd_getfriend,
    remfriend => \&tircd_remfriend,
    updatefriend => \&tircd_updatefriend,
    getfollower => \&tircd_getfollower,

    verify_ssl => \&tircd_verify_ssl,
    basicauth_login => \&twitter_basic_login,
    setup_authenticated_user => \&tircd_setup_authenticated_user,
    oauth_login_begin => \&twitter_oauth_login_begin,
    oauth_login_finish => \&twitter_oauth_login_finish,
    oauth_pin_ask => \&twitter_oauth_pin_ask,
    oauth_pin_entry => \&twitter_oauth_pin_entry,
    no_pin_received => \&tircd_oauth_no_pin_received,

    save_config => \&tircd_save_config,

    get_message_parts => \&tircd_get_message_parts,

    
  },
  ClientFilter		=> $filter, 
  ClientInput		=> \&irc_line,
  ClientConnected    	=> \&tircd_connect,
  ClientDisconnected	=> \&tircd_cleanup,
  Started 		=> \&tircd_setup
);    

$poe_kernel->run();                                                                
exit 0; 

########## STARTUP FUNCTIONS BEGIN

sub tircd_setup {
  $_[KERNEL]->call('logger','log',"tircd $VERSION started, using config from: $config_file.");
  $_[KERNEL]->call('logger','log',"Listening on: $config{'address'}:$config{'port'}."); 
  if ($config{'debug'}) {
    $_[KERNEL]->call('logger','log',"Using Net::Twitter::Lite version: $Net::Twitter::Lite::VERSION");
    $_[KERNEL]->call('logger','log',"Using LWP::UserAgent version: $LWP::UserAgent::VERSION");
    $_[KERNEL]->call('logger','log',"Using POE::Filter::IRCD version: $POE::Filter::IRCD::VERSION");
  }
}

#setup our logging session
sub logger_setup {
  my ($kernel, $heap, $type, $file) = @_[KERNEL, HEAP, ARG0, ARG1];
  $_[KERNEL]->alias_set('logger');
  
  my $handle = 0;
  if ($type eq 'file') {
    $handle = IO::File->new(">>$file");
  } elsif ($type eq 'stdout') {
    $handle = \*STDOUT;
  } elsif ($type eq 'stderr') {
    $handle = \*STDERR;
  }
  
  if ($handle) {
    #Win32 seems to blow up when trying to set FIONBIO on STDOUT/ERR
    $heap->{'file'} = ($^O eq 'MSWin32' && $type ne 'file') ? $handle : POE::Wheel::ReadWrite->new( Handle => $handle );
  }
}

########## 'INTERNAL' UTILITY FUNCTIONS
#log a message
sub logger_log {
  my ($heap, $msg, $from) = @_[HEAP, ARG0, ARG1];
  return if ! $heap->{'file'};
  
  $from = "[$from] " if defined $from;
  my $stamp = '['.localtime().'] ';
  if (ref $heap->{'file'} eq 'POE::Wheel::ReadWrite')  {
    $heap->{'file'}->put("$stamp$from$msg");
  } else {
    $heap->{'file'}->print("$stamp$from$msg\n");
  }
}

#trap twitter api errors
sub twitter_api_error {
  my ($kernel,$heap, $msg, $error) = @_[KERNEL, HEAP, ARG0, ARG1];
  
  if ($config{'debug'}) {
    $kernel->post('logger','log',$error->message().' '.$error->code().' '.$error,'debug/twitter_api_error');
  }

  if ($error) {
    $kernel->post('logger','log',$msg.' ('.$error->code() .' from Twitter API).',$heap->{'username'});  

    if ($error->code() == 429) {
      $msg .= ' Twitter API limit reached.';
    } else {
      $msg .= ' Twitter Fail Whale.';
    }
  }
  else {
    $kernel->post('logger','log',$msg.' (Unknown error from Twitter API).',$heap->{'username'});  

  }
  $kernel->yield('server_reply',461,'#twitter',$msg);
}

#update a friend's info in the heap
sub tircd_updatefriend {
  my ($heap, $new) = @_[HEAP, ARG0];  

  foreach my $friend (@{$heap->{'friends'}}) {
    if ($friend->{'id'} == $new->{'id'}) {
      $friend = $new;
      return 1;
    }
  }
  return 0;
}

#check to see if a given friend exists, and return it
sub tircd_getfriend {
  my ($heap, $target) = @_[HEAP, ARG0];
  
  foreach my $friend (@{$heap->{'friends'}}) {
    if ($friend->{'screen_name'} eq $target) {
      return $friend;
    }
  }
  return 0;
}

sub tircd_getfollower {
  my ($heap, $target) = @_[HEAP, ARG0];
  
  foreach my $follower (@{$heap->{'followers'}}) {
    if ($follower->{'screen_name'} eq $target) {
      return $follower;
    }
  }
  return 0;
}

sub tircd_remfriend {
  my ($heap, $target) = @_[HEAP, ARG0];
  
  my @tmp = ();
  foreach my $friend (@{$heap->{'friends'}}) {
    if ($friend->{'screen_name'} ne $target) {
      push(@tmp,$friend);
    }
  }
  $heap->{'friends'} = \@tmp;
}

#called once we have a user/pass, attempts to auth with twitter
sub tircd_login {
	my ($kernel, $heap, $data) = @_[KERNEL, HEAP, ARG0];

	if ($heap->{'twitter'}) { #make sure we aren't called twice
		return;
	}

	$heap->{'nt_params'}{'source'} = "tircd";

	# use SSL?
	if ($config{'use_ssl'}) {
		$heap->{'nt_params'}{'ssl'} = 1;
		# verify_ssl will drop user if SSL checks fail
		return unless($kernel->call($_[SESSION],'verify_ssl'));
	}

  # begin oauth authentication flow
  return $kernel->call($_[SESSION],'oauth_login_begin');
}

# oauth login flow
sub twitter_oauth_login_begin {
	my ($kernel, $heap) = @_[KERNEL, HEAP];
	$heap->{'nt_params'}{'consumer_key'} = $tw_oauth_con_key;
	$heap->{'nt_params'}{'consumer_secret'} = $tw_oauth_con_sec;

	eval "use Net::OAuth 0.16";
	if ($@) {
		$kernel->yield('server_reply',463,'Net::OAuth >= 0.16 is not installed');
		$kernel->yield('server_reply',463,'OAuth authentication requires Net::OAuth version 0.16 or greater.');
		$kernel->yield('shutdown');
	}

	$kernel->yield('server_reply',463,'OAuth authentication beginning.');

	$heap->{'twitter'} = Net::Twitter::Lite::WithAPIv1_1->new(%{$heap->{'nt_params'}});

	# load user config from disk for reusing tokens
	if (-d $config{'storage_path'}) {
		$heap->{'config'}   = eval {retrieve($config{'storage_path'} . '/' . $heap->{'username'} . '.config');};
	} 
	# if tokens exist in users config, attempt to re-use
	if ($heap->{'config'}->{'access_token'} && $heap->{'config'}->{'access_token_secret'}) {
		# If password is set in user state - check that is is correct
		if ($heap->{'config'}->{'password'} =~ m#[a-zA-Z0-9+/]{27}# ) {
			if ($heap->{'password'} ne $heap->{'config'}->{'password'}) {
				$kernel->post('logger','log','Connection refused with the supplied credentials.',$heap->{'username'});
				$kernel->yield('server_reply',464,'Connection refused with the supplied credentials.');
				$kernel->yield('shutdown'); #disconnect 'em if we cant verify password
				return;
			}
		}
		$heap->{'twitter'}->access_token($heap->{'config'}->{'access_token'});
		$heap->{'twitter'}->access_token_secret($heap->{'config'}->{'access_token_secret'});
		return if $kernel->call($_[SESSION],'oauth_login_finish');
	}

	unless($heap->{'twitter'}->authorized) {
		$kernel->call($_[SESSION],'oauth_pin_ask');
	}

	return 1;
}

# direct user to pin site
sub twitter_oauth_pin_ask {
	my ($kernel, $heap) = @_[KERNEL,HEAP];

    my $authorization_url = eval { $heap->{'twitter'}->get_authorization_url() };
    if ($@) {
	    $kernel->yield('server_reply',599,"Unable to retrieve authentication URL from Twitter.");
	    $kernel->yield('server_reply',599,"The Twitter API seems to be experiencing problems. Try again momentarily.");
	    $kernel->yield('shutdown');
        return 1;
    }

	$kernel->yield('server_reply',463,"Please authorize this connection at:");
	$kernel->yield('server_reply',463,$heap->{'twitter'}->get_authorization_url);
	$kernel->yield('server_reply',463,"To continue connecting, type /stats pin <PIN>, where <PIN> is the PIN returned by the twitter authorize page.");
	$kernel->yield('server_reply',463,"Some clients require you to use /quote stats pin <PIN>");
	# half an hour until disconnect
	$kernel->alarm('no_pin_received',time() + 1800);
	return 1;
}

# received pin msg
sub twitter_oauth_pin_entry {
	my ($kernel, $pin) = @_[KERNEL, ARG0];

	# clear ask timeout alarm
	$kernel->alarm('no_pin_received');
	return $kernel->call($_[SESSION],'oauth_login_finish',$pin);
}

sub twitter_oauth_login_finish {
	my ($kernel, $heap, $pin) = @_[KERNEL, HEAP, ARG0];

	# make token ask if pin provided
	if ($pin) {
		my ($access_token, $access_token_secret, $user_id, $username) = eval { $heap->{'twitter'}->request_access_token(verifier=>$pin) };
		if ($@) {
			if ($@ =~ m/401/) {
				$kernel->yield('server_reply',510,'Unable to authorize with this PIN. Please try again.');
			} else {
				$kernel->yield('server_reply',511,'Unknown error while authorizing. Please try again.');
			}
			$kernel->yield('oauth_pin_ask');
			return;
		}

		# check if already logged in
		if (exists $users{$username}) {
			$kernel->yield('server_reply',436,$username,'You are already connected to Twitter with this username.');
			$kernel->yield('shutdown');
			return 1;
		}

		# store tokens and user info in config for later use.
		$heap->{'config'}->{'access_token'} = $access_token;
		$heap->{'config'}->{'access_token_secret'} = $access_token_secret;
		$heap->{'config'}->{'user_id'} = $user_id;
		$heap->{'config'}->{'username'} = $username;
		$heap->{'username'} = $username;
	}

	# make sure we're happy, otherwise re-try PIN ask
	unless($heap->{'twitter'}->authorized) {
		$kernel->post('logger','log','Unable to retrieve access tokens for entered PIN.');
		$kernel->yield('server_reply',462,'Invalid PIN. Re-check PIN and try again.');
		$kernel->yield('oauth_pin_ask');
		return;
	}

	$kernel->yield('server_reply',399,'PIN accepted.');
	$kernel->yield('setup_authenticated_user');
	return 1;
}

sub tircd_setup_authenticated_user {
	my ($kernel, $heap) = @_[KERNEL, HEAP];

	#load our configs from disk if they exist
	if (-d $config{'storage_path'}) {
		$heap->{'channels'} = eval {retrieve($config{'storage_path'} . '/' . $heap->{'username'} . '.channels');};
	} 

	my @user_settings = qw(update_timeline update_directs timeline_count long_messages min_length max_splits join_silent filter_self shorten_urls convert_irc_replies store_access_tokens access_token access_token_secret auto_post display_ticker_slots show_realname expand_urls password);

	# update users config to contain all necessary settings, weed out unnecessary
	foreach my $s (@user_settings) {
		unless (exists($heap->{'config'}->{$s})) {
			$heap->{'config'}->{$s} = $config{$s};
		}
	}
	foreach my $k (keys %{$heap->{'config'}}) {
		if (!grep($_ eq $k, @user_settings)) {
			delete $heap->{'config'}->{$k};
		}
	}

	# If the client has connected with a password, and is authorized by twitter, 
	# encrypt and store password if it is not already stored
	if ($heap->{'password'} && !($heap->{'config'}->{'password'})) {
        $heap->{'config'}->{'password'} = $heap->{'password'};
        $kernel->yield('save_config');
	}

	if (!$heap->{'channels'}) {
		$heap->{'channels'} = {};
	}
   if (defined($heap->{'channels'}->{'__STATE'})){
      $heap->{'timeline_since_id'} = $heap->{'channels'}->{'__STATE'}->{'timeline_since_id'} || 0;
      $heap->{'replies_since_id'} = $heap->{'channels'}->{'__STATE'}->{'replies_since_id'} || 0;
      $heap->{'direct_since_id'} = $heap->{'channels'}->{'__STATE'}->{'direct_since_id'} || 0;
   }


	#we need this for the tinyurl support and others
	$heap->{'ua'} = LWP::UserAgent->new;
	$heap->{'ua'}->timeout(10);
	$heap->{'ua'}->env_proxy();

	# allow channel joining
	$heap->{'authenticated'} = 1;

	#stash the username in a list to keep 'em from rejoining
	$users{$heap->{'username'}} = 1;

	#some clients need this shit
	$kernel->yield('server_reply','001',"Welcome to tircd $heap->{'username'}");
	$kernel->yield('server_reply','002',"Your host is tircd running version $VERSION");
	$kernel->yield('server_reply','003',"This server was created just for you!");
	$kernel->yield('server_reply','004',"tircd $VERSION i int");

	#show 'em the motd
	$kernel->yield('MOTD');  
}

sub tircd_oauth_no_pin_received {
	my ($kernel, $heap) = @_[KERNEL, HEAP];

	# we didn't receive a pin in time
	$kernel->post('logger','log','No PIN entered, disconnecting user: ',$heap->{'username'});
	$kernel->yield('server_reply',532,'Never received a PIN. Disconnecting');
	$kernel->yield('shutdown'); #disconnect 'em if we cant
	return;
}

sub tircd_verify_ssl {
	my($kernel) = @_[KERNEL];
	# unless we have a bundle or directory of certs to verify against, ssl is b0rked
	unless($ENV{'HTTPS_CA_FILE'} or $ENV{'HTTPS_CA_DIR'}) {
		$kernel->yield('logger','log',"You must provide the environment variable HTTPS_CA_FILE or HTTPS_CA_DIR before starting tircd.pl in order to verify SSL certificates.");
		$kernel->yield('server_reply',462,'Unable to verify SSL certificate');
		$kernel->yield('shutdown'); #disconnect 'em if we cant
		return;
	}

	# check ssl cert using LWP
	my $api_check = Net::Twitter::Lite::WithAPIv1_1->new;
	my $sslcheck = LWP::UserAgent->new;
	my $apiurl = URI->new($api_check->{'apiurl'});
	# second level domain, aka domain.tld. if this is present in the certificate, we are happy
	my $SLD = $apiurl->host;
	$SLD =~ s/.*\.([^.]*\.[^.]*)/$1/;;



	# if-ssl-cert-subject causes the certificate subject line to be checked against the regex in its value
	# upon checking the certificate, it will cancel the request and set the HTTP::Response is_error to 1 for us
	$sslcheck->default_header("If-SSL-Cert-Subject" => "CN=(.*\.){0,1}$SLD");
	# knock politely
	my $sslresp = $sslcheck->get($apiurl); 

	# cert failed to verify against local bundle/ca_dir
	if( $sslresp->header('client-ssl-warning') ) {
		$kernel->yield('logger','log',"Unable to verify server certificate against local authority.");
		$kernel->yield('server_reply',462,'Unable to verify SSL certificate.');
		$kernel->yield('shutdown'); 
		return;
	}

	# cert response failed to be for expected domain
	if( $sslresp->is_error && $sslresp->code == 500 ) {
		$kernel->yield('logger','log',"Hostname (CN) of SSL certificate did not match domain being accessed, someone is doing something nasty!");
		$kernel->yield('server_reply',462,'SSL certificate has invalid Common Name (CN).');
		$kernel->yield('shutdown'); 
		return;
	}

	# all SLL checks passed
	return 1;
}

sub tircd_connect {
  my ($kernel, $heap) = @_[KERNEL, HEAP];
  $kernel->post('logger','log',$heap->{'remote_ip'}.' connected.');
}


sub tircd_cleanup {
  my ($kernel, $heap) = @_[KERNEL, HEAP];
  $kernel->post('logger','log',$heap->{'remote_ip'}.' disconnected.',$heap->{'username'});

  # stop the oauth no pin entry alarm
  $kernel->alarm('no_pin_received');
  
  #delete the username
  delete $users{$heap->{'username'}};

  #remove our timers so the session will die
  $kernel->delay('twitter_timeline');  
  $kernel->delay('twitter_direct_messages');

  #mark all channels as not joined for the next reload
  foreach my $chan (keys %{$heap->{'channels'}}) {
      $heap->{'channels'}->{$chan}->{'joined'} = 0;
  }

  $kernel->yield('save_config');

  $kernel->yield('shutdown');
}

# Save config
sub tircd_save_config {
  my ($kernel, $heap) = @_[KERNEL, HEAP];
  # if storage_path directory doesn't exist, attempt to create
  unless ( -e $config{'storage_path'} && -d $config{'storage_path'} ) {
    unless (mkdir ($config{'storage_path'})) {
      $kernel->post('logger','log','Was unable to create storage_path at ' . $config{'storage_path'} . ' .' . $!);  
      return 0;
    }
  }
  
  #if we can, save user_settings and state for next time
  if ($config{'storage_path'} && -d $config{'storage_path'} && -w $config{'storage_path'}) {

    # save incoming tweet state in hidden channel
    $heap->{'channels'}->{'__STATE'}->{'timeline_since_id'} = $heap->{'timeline_since_id'};
    $heap->{'channels'}->{'__STATE'}->{'replies_since_id'} = $heap->{'replies_since_id'};
    $heap->{'channels'}->{'__STATE'}->{'direct_since_id'} = $heap->{'direct_since_id'};

    # clip out tokens if requested
    my $store_config = $heap->{'config'};
    if ($heap->{'config'}->{'store_access_tokens'} == 0) {
      delete $store_config->{'access_token'};
      delete $store_config->{'access_token_secret'};
    }
    
    eval {store($store_config,$config{'storage_path'} . '/' . $heap->{'username'} . '.config');};
    eval {store($heap->{'channels'},$config{'storage_path'} . '/' . $heap->{'username'} . '.channels');};
    $kernel->post('logger','log','Saving configuration.',$heap->{'username'});  
    return 1;
  } else {
    $kernel->post('logger','log','storage_path is not set or is not writable, not saving configuration.',$heap->{'username'});  
    return 0;
  }
}


########## 'INTERNAL' IRC I/O FUNCTIONS
#called everytime we get a line from an irc server
#trigger an event and move on, the ones we care about will get trapped
sub irc_line {
  my  ($kernel, $data) = @_[KERNEL, ARG0];
  if ($config{'debug'}) {
    if (!$data->{'params'}) {
      $data->{'params'} = [];
    }
    $kernel->post('logger','log',$data->{'prefix'}.' '.$data->{'command'}.' '.join(' ',@{$data->{'params'}}),'debug/irc_line');
  }
  $kernel->yield($data->{'command'},$data); 
}

#send a message that looks like it came from a user
sub irc_user_msg {
  my ($kernel, $heap, $code, $username, @params) = @_[KERNEL, HEAP, ARG0, ARG1, ARG2..$#_];

  foreach my $p (@params) { #fix multiline tweets, submitted a patch to Filter::IRCD to fix this in the long term
    $p =~ s/\n/ /g;
  }

  if ($config{'debug'}) {
    $kernel->post('logger','log',$username.' '.$code.' '.join(' ',@params),'debug/irc_user_msg');
  }

  $heap->{'client'}->put({
    command => $code,
    prefix => "$username!$username\@twitter",
    params => \@params
  });
}

#send a message that comes from the server
sub irc_reply {
  my ($kernel, $heap, $code, @params) = @_[KERNEL, HEAP, ARG0, ARG1..$#_];

  foreach my $p (@params) {
    $p =~ s/\n/ /g;
  }

  if ($code ne 'PONG' && $code ne 'MODE' && $code != 436) {
    unshift(@params,$heap->{'username'}); #prepend the target username to the message;
  }

  if ($config{'debug'}) {
    $kernel->post('logger','log',':tircd '.$code.' '.join(' ',@params),'debug/irc_reply');
  }

  $heap->{'client'}->put({
    command => $code,
    prefix => 'tircd', 
    params => \@params     
  }); 
}


########### IRC EVENT FUNCTIONS

sub irc_pass {
  my ($heap, $data) = @_[HEAP, ARG0];
  $heap->{'password'} = sha1_base64($data->{'params'}[0]); #encrypt stash the password for later
}

sub irc_nick {
  my ($kernel, $heap, $data) = @_[KERNEL, HEAP, ARG0];

  if ($heap->{'username'}) { #if we've already got their nick, don't let them change it
    $kernel->yield('server_reply',433,'Changing nicks once connected is not currently supported.');    
    return;
  }

  $heap->{'username'} = $data->{'params'}[0]; #stash the username for later

  if (!$heap->{'twitter'}) {
    $kernel->yield('login');
  }
}

sub irc_user {
  my ($kernel, $heap, $data) = @_[KERNEL, HEAP, ARG0];

  # proceed to login if we have the nick and no connection
  if ($heap->{'username'} && !$heap->{'twitter'}) {
    $kernel->yield('login');
  }
}

#return the MOTD
sub irc_motd {
  my ($kernel, $heap, $data) = @_[KERNEL, HEAP, ARG0];

  $kernel->yield('server_reply',375,'- tircd Message of the Day -');

  my $ua = LWP::UserAgent->new;
  $ua->timeout(5);
  $ua->env_proxy();
  my $res = $ua->get('http://tircd.googlecode.com/svn/trunk/motd.txt');
  
  if (!$res->is_success) {
    $kernel->yield('server_reply',372,"- Unable to get the MOTD.");
  } else {
    my @lines = split(/\n/,$res->content);
    foreach my $line (@lines) {
      $kernel->yield('server_reply',372,"- $line");
    }
  }
  
  $kernel->yield('server_reply',376,'End of /MOTD command.');
}

sub irc_join {
  my ($kernel, $heap, $data) = @_[KERNEL, HEAP, ARG0];

  unless($heap->{'authenticated'}) {
	$kernel->yield('server_reply',508,"Unable to join ", $data->{'params'}[0],".");
	$kernel->yield('server_reply',509,"Connection not yet authorized.");
	return;
  }

  my @chans = split(/\,/,$data->{'params'}[0]);
  foreach my $chan (@chans) {
    $chan =~ s/\s//g;
    #see if we've registered an event handler for a 'special channel' (currently only #twitter)
    if ($kernel->call($_[SESSION],$chan,$chan)) {
      next;
    }
    
    #we might have something saved already, if not prep a new channel
    if (!exists $heap->{'channels'}->{$chan} ) {
      $heap->{'channels'}->{$chan} = {};
      $heap->{'channels'}->{$chan}->{'names'}->{$heap->{'username'}} = '@';  
    }
    
    $heap->{'channels'}->{$chan}->{'joined'} = 1;
    
    #otherwise, prep a blank channel  
    $kernel->yield('user_msg','JOIN',$heap->{'username'},$chan);	
    $kernel->yield('server_reply',332,$chan,"$chan");
    $kernel->yield('server_reply',333,$chan,'tircd!tircd@tircd',time());


    #send the /NAMES info
    my $all_users = '';
    foreach my $name (keys %{$heap->{'channels'}->{$chan}->{'names'}}) {
      $all_users .= $heap->{'channels'}->{$chan}->{'names'}->{$name} . $name .' ';
    }
    $kernel->yield('server_reply',353,'=',$chan,$all_users);
    $kernel->yield('server_reply',366,$chan,'End of /NAMES list');
    
    #restart the searching
    if ($heap->{'channels'}->{$chan}->{'topic'}) {
      $kernel->yield('user_msg','TOPIC',$heap->{'username'},$chan,$heap->{'channels'}->{$chan}->{'topic'});
      #  Searching is started when topic is set so this is redundant and causes frequent errors from twitter
      # $kernel->yield('twitter_search',$chan);
      # $kernel->post('logger','log','Started search after rejoin - ' . $heap->{'channels'}->{$chan}->{'topic'}  . ' - ' . $heap->{'channels'}->{$chan}->{'search_since_id'});
    }
  }
}

sub irc_part {
  my ($kernel, $heap, $data) = @_[KERNEL, HEAP, ARG0];
  my $chan = $data->{'params'}[0];
  
  if ($heap->{'channels'}->{$chan}->{'joined'}) {
    delete $heap->{'channels'}->{$chan};
    $kernel->yield('user_msg','PART',$heap->{'username'},$chan);
  } else {
    $kernel->yield('server_reply',442,$chan,"You're not on that channel");
  }
}

sub irc_mode { #ignore all mode requests except ban which is a block (send back the appropriate message to keep the client happy)
#this whole thing is messy as hell, need to refactor this function
  my ($kernel, $heap, $data) = @_[KERNEL, HEAP, ARG0];
  my $target = $data->{'params'}[0];
  my $mode = $data->{'params'}[1];
  my $opts = $data->{'params'}[2];

  #extract the nick from the banmask
  my ($nick,$host) = split(/\!/,$opts,2);
    $nick =~ s/\*//g;
    if (!$nick) {
      $host =~ s/\*//g;
    if ($host =~ /(.*)\@twitter/) {
      $nick = $1;
    }
  }

  if ($target =~ /^\#/) {
    if ($mode eq 'b') {
      $kernel->yield('server_reply',368,$target,'End of channel ban list');
      return;
    }
    if ($target eq '#twitter') {
      if ($mode eq '+b' && $target eq '#twitter') {
        my $user = eval { $heap->{'twitter'}->create_block($nick) };
        my $error = $@;
        if ($user) {
          $kernel->yield('user_msg','MODE',$heap->{'username'},$target,$mode,$opts);
        } else {
          if (ref $error && $error->isa("Net::Twitter::Lite::Error") && $error->code() >= 400) {
            $kernel->call($_[SESSION],'twitter_api_error','Unable to block user.',$error);
          } else {
            $kernel->yield('server_reply',401,$nick,'No such nick/channel');
          }
        }
        return;        
      } elsif ($mode eq '-b' && $target eq '#twitter') {
        my $user = eval { $heap->{'twitter'}->destroy_block($nick) };
        my $error = $@;
        if ($user) {
          $kernel->yield('user_msg','MODE',$heap->{'username'},$target,$mode,$opts);
        } else {
          if (ref $error && $error->isa("Net::Twitter::Lite::Error") && $error->code() >= 400) {
            $kernel->call($_[SESSION],'twitter_api_error','Unable to unblock user.',$error);
          } else {
            $kernel->yield('server_reply',401,$nick,'No such nick/channel');
          }
        }
        return;
      }
    }
    if (!$mode) {        
      $kernel->yield('server_reply',324,$target,"+t");
    }
    return;
  }
  
  $kernel->yield('user_msg','MODE',$heap->{'username'},$target,'+i');
}

sub irc_who {
  my ($kernel, $heap, $data) = @_[KERNEL, HEAP, ARG0];
  my $target = $data->{'params'}[0];
  if ($target =~ /^\#/) {
    if (exists $heap->{'channels'}->{$target}) {
      foreach my $name (keys %{$heap->{'channels'}->{$target}->{'names'}}) {
        if (my $friend = $kernel->call($_[SESSION],'getfriend',$name)) {
          $kernel->yield('server_reply',352,$target,$name,'twitter','tircd',$name,'G'.$heap->{'channels'}->{$target}->{'names'}->{$name},"0 $friend->{'name'}");
        }
      }      
    }
  } else { #only support a ghetto version of /who right now, /who ** and what not won't work
    if (my $friend = $kernel->call($_[SESSION],'getfriend',$target)) {
        $kernel->yield('server_reply',352,'*',$friend->{'screen_name'},'twitter','tircd',$friend->{'screen_name'}, "G","0 $friend->{'name'}");
    }
  }
  $kernel->yield('server_reply',315,$target,'End of /WHO list'); 
}


sub irc_whois {
  my ($kernel, $heap, $data) = @_[KERNEL, HEAP, ARG0];
  my $target = $data->{'params'}[0];
  
  my $friend = $kernel->call($_[SESSION],'getfriend',$target);
  my $isfriend = 1;
  my $error;
  
  if (!$friend) {#if we don't have their info already try to get it from twitter, and track it for the end of this function
    $friend = eval { $heap->{'twitter'}->show_user({screen_name => $target}) };
    $error = $@;
    $isfriend = 0;
  }

  if (ref $error && $error->isa("Net::Twitter::Lite::Error") && $error->code() == 404) {
    $kernel->yield('server_reply',402,$target,'No such server');
    return;
  }

  if (!$friend && ref $error && $error->isa("Net::Twitter::Lite::Error") && $error->code() >= 400) {
    $kernel->call($_[SESSION],'twitter_api_error','Unable to get user information.',$error);
    return;
  }        

  if ($friend) {
    $kernel->post('logger','log',"Received user information for $target from Twitter.",$heap->{'username'});
    $kernel->yield('server_reply',311,$target,$target,'twitter','*',$friend->{'name'});
    
    #send a bunch of 301s to convey all the twitter info, not sure if this is totally legit, but the clients I tested with seem ok with it
    if ($friend->{'location'}) {
      $kernel->yield('server_reply',301,$target,"Location: $friend->{'location'}");
    }

    if ($friend->{'url'}) {
      $kernel->yield('server_reply',301,$target,"Web: $friend->{'url'}");
    }

    if ($friend->{'description'}) {
      $kernel->yield('server_reply',301,$target,"Bio: $friend->{'description'}");
    }

    if ($friend->{'status'}->{'text'}) {
      $kernel->yield('server_reply',301,$target,"Last Update: ".$friend->{'status'}->{'text'});
    }

    if ($target eq $heap->{'username'}) { #if it's us, then add the rate limit info to
      my $rate = eval { $heap->{'twitter'}->rate_limit_status() };
      $kernel->yield('server_reply',301,$target,'API Usage: '.($rate->{'hourly_limit'}-$rate->{'remaining_hits'})." of $rate->{'hourly_limit'} calls used.");
      $kernel->post('logger','log','Current API usage: '.($rate->{'hourly_limit'}-$rate->{'remaining_hits'})." of $rate->{'hourly_limit'}",$heap->{'username'});
    }

    #treat their twitter client as the server
    my $server; my $info;
    # if ($friend->{'status'}->{'source'} =~ /\<a href="(.*)"\>(.*)\<\/a\>/) { #not sure this regex will work in all cases
    # Fix for issue 87
    if ($friend->{'status'}->{'source'} =~ /\<a href="([^"]*)".*\>(.*)\<\/a\>/) {
      $server = $2;
      $info = $1;
    } else {
      $server = 'web';
      $info = 'http://www.twitter.com/';
    }
    $kernel->yield('server_reply',312,$target,$server,$info);
    
    #set their idle time, to the time since last message (if we have one, the api won't return the most recent message for users who haven't updated in a long time)
    my $diff = 0;
    my %mon2num = qw(Jan 0 Feb 1 Mar 2 Apr 3 May 4 Jun 5 Jul 6 Aug 7 Sep 8 Oct 9 Nov 10 Dec 11);
    if ($friend->{'status'}->{'created_at'} =~ /\w+ (\w+) (\d+) (\d+):(\d+):(\d+) [+|-]\d+ (\d+)/) {
        my $date = timegm($5,$4,$3,$2,$mon2num{$1},$6);
        $diff = time()-$date;
    }
    $kernel->yield('server_reply',317,$target,$diff,'seconds idle');

    my $all_chans = '';
    foreach my $chan (keys %{$heap->{'channels'}}) {
      if (exists $heap->{'channels'}->{$chan}->{'names'}->{$friend->{'screen_name'}}) {
        $all_chans .= $heap->{'channels'}->{$chan}->{'names'}->{$friend->{'screen_name'}}."$chan ";
      }
    }
    if ($all_chans ne '') {
      $kernel->yield('server_reply',319,$target,$all_chans);
    }
  }

  $kernel->yield('server_reply',318,$target,'End of /WHOIS list'); 
}

sub irc_stats {
  my ($kernel, $heap, $data) = @_[KERNEL, HEAP, ARG0];
  my $key = lc($data->{'params'}[0]);
  my $val = $data->{'params'}[1];  
  
  $key = '--' if (!$key || $key eq 'm');
  if ($key eq '--') {
    $kernel->yield('server_reply',212,$key,"Current config settings:");
    foreach my $k (sort keys %{$heap->{'config'}}) {
      $kernel->yield('server_reply',212,$key,"  $k: ".$heap->{'config'}->{$k});  
    }
    $kernel->yield('server_reply',212,$key,"Use '/stats <key> <value>' to change a setting.");
    $kernel->yield('server_reply',212,$key,"Example: /stats join_silent 1");
  } elsif ($key =~ m/pin/i) {
    $kernel->yield('oauth_pin_entry',$val);
    return;
  } else {
    if (exists $heap->{'config'}->{$key}) {
      # Allow user to change password via stats-command
      # Not sure we really want to do this...
      if (($key =~ m/password/i) && ($val)) {
        $val = sha1_base64($val);
      }
      $heap->{'config'}->{$key} = $val;
      $kernel->yield('server_reply',212,$key,"set to $val");
      # if val is 0, $delay becomes undef, which kills twitter_timeline alarms in place
      if ($key =~ m/update_timeline/i) {
        my $delay = ($val) ? $val:undef;
        $kernel->delay('twitter_timeline',$delay);
      }
      if ($key =~ m/update_directs/i) {
        my $delay = ($val) ? $val:undef;
        $kernel->delay('twitter_direct_messages',$delay);
      }
      $kernel->yield('save_config');
    } 
  }
  $kernel->yield('server_reply',219,$key,'End of /STATS request');
}

sub irc_privmsg {
  my ($kernel, $heap, $data) = @_[KERNEL, HEAP, ARG0];
  
  my $target = $data->{'params'}[0];
  my $msg  = $data->{'params'}[1];

  #handle /me or ACTION requests properly
  #this begins the slipperly slope of manipulating user input
  $msg =~ s/\001ACTION (.*)\001/\*$1\*/;
  
  # Targeted to a channel, post or offerbot command
  if ($target =~ /^#/) {
    if (!exists $heap->{'channels'}->{$target}) {
      $kernel->yield('server_reply',404,$target,'Cannot send to channel');
      return;
    }
  
    $target = '#twitter'; #we want to force all topic changes and what not into twitter for now

    # We want to handle !-commands even if auto_post is set to true
    if ($msg =~ /^\s*!/i) {
      $kernel->post('logger','log',"Saw offerbot command of $msg",$heap->{'username'}) if $config{'debug'} >= 1;
      $kernel->yield('handle_command', $msg, $target);
    } elsif ($heap->{'config'}->{'auto_post'} == 1) {
      $kernel->yield('twitter_post_tweet',$target, $msg);
    }
     
  } else { 
    # PMs are DMs
    $kernel->yield('twitter_send_dm',$target, $msg);
  }
}    


sub twitter_post_tweet {
   # throwaway target for now
   my($kernel, $heap, $target, $msg) = @_[KERNEL, HEAP, ARG0, ARG1];
   #shorten the URL
   if (eval("require URI::Find;") && $heap->{'config'}->{'shorten_urls'}) {
      my $finder = URI::Find->new(sub {
            my $uriobj = shift;
            my $uri = shift;

            if ($uri !~ /^http:/) {
            return $uri;
            }

            # Do not shorten twice - heuristics!
            if (length($uri) < 30) {
            return $uri;
            }


            my $res = $heap->{'ua'}->get("http://tinyurl.com/api-create.php?url=$uri");
            if ($res->is_success) {
            return $res->content;
            } else {
            return $uri;
            }
            });
      $finder->find(\$msg);
   }

	#Tweak the @replies
   if ($msg =~ /^(\w+)\: / && $heap->{'config'}->{'convert_irc_replies'}) {
	# @Olatho - changing ALL first-words that end with : to @, not only nicks on #Twitter
	# - I sometimes reply to people that I do not follow, and want them converted as well
      $msg =~ s/^(\w+)\: /\@$1 /;
   }

   my @msg_parts = $kernel->call($_[SESSION],'get_message_parts',$target, $msg);
   unless (@msg_parts) {
      return 0;
   }
   
   my $update;
   for my $part (@msg_parts) {
      $update = eval { $heap->{'twitter'}->update($part) };
      my $error = $@;
      if (!$update && ref $error && $error->isa("Net::Twitter::Lite::Error") && $error->code() >= 400) {
         $kernel->call($_[SESSION],'twitter_api_error','Unable to update status.',$error);
         return;
      } 
   }

   #update our own friend record
   my $me = $kernel->call($_[SESSION],'getfriend',$heap->{'username'});
   $me = $update->{'user'};
   $me->{'status'} = $update;
   $kernel->call($_[SESSION],'updatefriend',$me);

	#keep the topic updated with our latest tweet  
   $kernel->yield('user_msg','TOPIC',$heap->{'username'},$target,"$heap->{'username'}'s last update: $msg");
	# Olatho - Fixing duplicate topic-changes
   $heap->{'channels'}->{$target}->{'topic'} = $msg;

   $kernel->post('logger','log','Updated status.',$heap->{'username'});
}

sub twitter_send_dm {
    my($kernel, $heap, $target, $msg) = @_[KERNEL, HEAP, ARG0, ARG1];

    my @msg_parts = $kernel->call($_[SESSION],'get_message_parts',$target, $msg);

    # if parts undefined, message too long and not split
    unless(@msg_parts) {
        return 0;
    }
    
    $kernel->post('logger','log',"Sending DM with " . scalar(@msg_parts) . " pieces.", $heap->{'username'});
    for my $part (@msg_parts) {
        my $dm = eval { $heap->{'twitter'}->new_direct_message({user => $target, text => $part}) };
        if (!$dm) {
            $kernel->yield('server_reply',401,$target,"Unable to send part or all of last direct message.  Perhaps $target isn't following you?");
            $kernel->post('logger','log',"Unable to send direct message to $target",$heap->{'username'});
        } else {
            $kernel->post('logger','log',"Sent direct message to $target",$heap->{'username'});
        }
    }
}

sub twitter_retweet_tweet {
    my($kernel, $heap, $tweet_id) = @_[KERNEL, HEAP, ARG0];

    unless($tweet_id) {
        $kernel->yield('user_msg','PRIVMSG',$heap->{'username'},"#twitter","Retweet requires a tweet-id.");
        return;
    }

    $kernel->post('logger','log','Retweeting status:'. $tweet_id);
    my $rt = eval { $heap->{'twitter'}->retweet($tweet_id) };
    my $error = $@;
    if (!$rt && ref $error && $error->isa("Net::Twitter::Lite::Error") && $error->code() >= 400) {
        $kernel->yield('user_msg','PRIVMSG',$heap->{'username'},"#twitter","Retweet failed. Try again shortly.");
        $kernel->call($_[SESSION],'twitter_api_error','Unable to retweet status.',$error);
        return;
    } 

    $kernel->yield('user_msg','PRIVMSG',$heap->{'username'},"#twitter","Retweet Successful.");
}

sub twitter_reply_to_tweet {
    my($kernel, $heap, $tweet_id, $msg) = @_[KERNEL, HEAP, ARG0, ARG1];
    $kernel->post('logger','log',"Replying to ($tweet_id) with ($msg)",$heap->{'username'}) if $config{'debug'} >=2;
    my $errd;
    my $target = "#twitter";

    my @msg_parts = $kernel->call($_[SESSION],'get_message_parts',$target, $msg);

    unless(@msg_parts) {
        return 0;
    }

    for my $part (@msg_parts) {
        my $update = eval { $heap->{'twitter'}->update({ "status" => $msg, "in_reply_to_status_id" => $tweet_id}) };
        my $error = $@;
        if (!$update && ref $error && $error->isa("Net::Twitter::Lite::Error") && $error->code() >= 400) {
            $errd = 1;
            $kernel->yield('user_msg','PRIVMSG',$heap->{'username'},"#twitter","Reply failed.");
            $kernel->call($_[SESSION],'twitter_api_error','Unable to update status.',$error);
            return;
        } 
    }
    unless ($errd) {
        $kernel->yield('user_msg','PRIVMSG',$heap->{'username'},"#twitter","Reply Successful.");
    }
}

# allow user to control updating / message attribution / etc with offerbot type
# commands
sub irc_twitterbot_command {
  my ($kernel, $heap, $command, $target) = @_[KERNEL, HEAP, ARG0, ARG1];
    $kernel->post('logger','log',"Got to tircdbot area",$heap->{'username'}) if $config{'debug'} >=2;

    my (@arg) = split / /, $command;

    # some processes require tweet-id, if twid is true, tweet-id is looked-up
    # and replaces short hash before method is called
    my @proc;
    @proc = (
        { 'cmdmatch' => 'refresh|up|update',
            'help' => "![update|up|refresh] - Updates the #twitter stream immediately.",
            'exec' => sub {
                    $kernel->yield('twitter_timeline');
                    $kernel->yield('twitter_direct_messages');
                },
        },

        { 'cmdmatch' => 'l|length',
            'argmatch' => '.',
            'help' => '![length|l] <text> - Returns the length in characters of a message.',
            'exec' => sub {
                    my ($cmd, @msg) = @_;
                    $kernel->yield('user_msg','PRIVMSG',"tircdbot","#twitter","Number of characters: " . length(join(" ",@msg)));
            },
        },

        { 'cmdmatch' => 'tweet|t',
            'argmatch' => '\S+.',
            'help' => "![tweet|t] <text of tweet> - Posts the given text as an update to your feed.",
            'exec' => sub {
                    my ($cmd, @msg) = @_;
                    $kernel->yield('twitter_post_tweet', '#twitter', join(" ",@msg));
            },
        },

        { 'cmdmatch' => 'retweet|rt',
            'argmatch' => '[0-9a-f]{3}\b',
            'twid' => 1,
            'help' => "![retweet|rt] <tweed-id> - Posts a retweet. tweet-id is the 3 digit code preceding the tweet.",
            'exec' => sub {
                    my ($cmd, $rt_id) = @_;
                    $kernel->yield('twitter_retweet_tweet',$rt_id);
            },
        },

        { 'cmdmatch' => 'reply|re',
            'argmatch' => '[0-9a-f]{3}\b',
            'twid' => 1,
            'help' => "![reply|re] <tweet-id> <message text> - Replies to a tweet. tweet-id is a the 3 digit code preceding the tweet.",
            'exec' => sub {
                    my ($cmd, $rt_id, @msg) = @_;
                    $kernel->yield('twitter_reply_to_tweet',$rt_id,join(" ",@msg));
            },
        },

        { 'cmdmatch' => 'conv|conversation',
            'argmatch' => '[0-9a-f]{3}\b',
            'twid' => 1,
            'help' => "![conversation|conv] <tweet-id> - Replay a conversation from begining. If tweet is not a reply, shows related tweets.",
            'exec' => sub {
                    my ($cmd, $tw_id) = @_;
                    $kernel->yield('twitter_conversation', $tw_id);
            },
        },

        # arg should be limited to 15char, but some UNs are grandfathered to be longer.
        { 'cmdmatch' => 'add|invite|follow',
            'argmatch' => '\w',
            'help' => '![add|invite|follow] <username> - Begin following the specified twitter username.',
            'exec' => sub {
                    my ($cmd, $add_user) = @_;
                    my $data = { 'params' => [$add_user, '#twitter'] };
                    $kernel->yield('INVITE', $data);
            },
        },

        { 'cmdmatch' => 'remove|kick|unfollow',
            'argmatch' => '\w',
            'help' => '![remove|kick|unfollow] <username> - Remove the username from the list of people your account follows.',
            'exec' => sub {
                    my ($cmd, $del_user) = @_;
                    my $data = { 'params' => [ '#twitter', $del_user ] };
                    $kernel->yield('KICK', $data);
            },
        },

        # best effort, no error checking
        { 'cmdmatch' => 'save',
            'help' => '!save - Saves twitter-username specific configuration immediately.',
            'exec' => sub {
                    $kernel->yield('save_config');
            },
        },

        { 'cmdmatch' => 'h|help',
            'help' => "!help - Shows this help message.",
            'exec' => sub {
                    $kernel->yield('user_msg','PRIVMSG',"tircdbot","#twitter","Sending you the help screen as a message.");
                    $kernel->yield('user_msg','PRIVMSG',"tircdbot",$heap->{'username'},"Tircd Command List");
                    $kernel->yield('user_msg','PRIVMSG',"tircdbot",$heap->{'username'},"Commands listed in [abc|a] form mean that 'a' is an alias for 'abc'");
                    for (@proc) {
                        $kernel->yield('user_msg','PRIVMSG',"tircdbot",$heap->{'username'},$_->{'help'});
                    }
            },
        },
    );

    # compare command to cmdmatch, verify args against argmatch (or error), convert short tweet-ids into real tweeit-ids, do something
    for my $p (@proc) {
        # scan proc table to find matching command
        my ($cmdmatch, $argmatch) = ($p->{'cmdmatch'},$p->{'argmatch'});
        if ($arg[0] =~ m/^\s*!($cmdmatch)\b/i) {
            my $cmdargs = join(" ",@arg);
            # check argument formatting 
            if ($cmdargs =~ /^\s*!($cmdmatch)\s*($argmatch)/i) {
                # convert short tweet-id to real id
                if ($p->{'twid'}) {
                    my $tw_id = $heap->{'timeline_ticker'}->{$arg[1]};
                    unless ($tw_id) {
                        $kernel->yield('user_msg','PRIVMSG',"tircdbot","#twitter","Tweet id of: " . $arg[1] . " was not found.");
                        return;
                    }
                    $arg[1] = $tw_id;
                }
                # run the coderef with the updated @arg
                &{$p->{'exec'}}(@arg);
                return 1;
            } else {
                $kernel->yield('user_msg','PRIVMSG',"tircdbot","#twitter",$p->{'help'});
                return;
            }
        }
    }
}

#allow the user to follow new users by adding them to the channel
sub irc_invite {
  my ($kernel, $heap, $data) = @_[KERNEL, HEAP, ARG0];
  my $target = $data->{'params'}[0];
  my $chan = $data->{'params'}[1];

  if (!$heap->{'channels'}->{$chan}->{'joined'}) {
    $kernel->yield('server_reply',442,$chan,"You're not on that channel");
    return;
  }

  if (exists $heap->{'channels'}->{$chan}->{'names'}->{$target}) {
    $kernel->yield('server_reply',443,$target,$chan,'is already on channel');
    return;
  }

  if ($chan ne '#twitter') { #if it's not our main channel, just fake the user in, if we already follow them
    if (exists $heap->{'channels'}->{'#twitter'}->{'names'}->{$target}) {
      $heap->{'channels'}->{$chan}->{'names'}->{$target} = $heap->{'channels'}->{'#twitter'}->{'names'}->{$target};
      $kernel->yield('server_reply',341,$target,$chan);
      $kernel->yield('user_msg','JOIN',$target,$chan);
      if ($heap->{'channels'}->{$chan}->{'names'}->{$target} ne '') {
        $kernel->yield('server_reply','MODE',$chan,'+v',$target);
      }
    } else {
      $kernel->yield('server_reply',481,"You must invite the user to the #twitter channel first.");    
    }
    return;      
  }

  #if it's the main channel, we'll start following them on twitter
  my $user = eval { $heap->{'twitter'}->create_friend({id => $target}) };
  my $error = $@;
  if ($user) {
    if (!$user->{'protected'}) {
      #if the user isn't protected, and we are following them now, then have 'em 'JOIN' the channel
      push(@{$heap->{'friends'}},$user);
      $kernel->yield('server_reply',341,$user->{'screen_name'},$chan);
      $kernel->yield('user_msg','JOIN',$user->{'screen_name'},$chan);
      $kernel->post('logger','log',"Started following $target",$heap->{'username'});
      if ($kernel->call($_[SESSION],'getfollower',$user->{'screen_name'})) {
        $heap->{'channels'}->{$chan}->{'names'}->{$target} = '+';
        $kernel->yield('server_reply','MODE',$chan,'+v',$target);        
      } else {
        $heap->{'channels'}->{$chan}->{'names'}->{$target} = '';
      }
    } else {
      #show a note if they are protected and we are waiting 
      #this should technically be a 482, but some clients were exiting the channel for some reason
      $kernel->yield('server_reply',481,"$target\'s updates are protected.  Request to follow has been sent.");
      $kernel->post('logger','log',"Sent request to follow $target",$heap->{'username'});      
    }
  } else {
    if (ref $error && $error->isa("Net::Twitter::Lite::Error") && $error->code() >= 400 && $error->code() != 403) {
      $kernel->call($_[SESSION],'twitter_api_error','Unable to follow user.',$error);    
    } else {
      $kernel->yield('server_reply',401,$target,'No such nick/channel');
      $kernel->post('logger','log',"Attempted to follow non-existant user $target",$heap->{'username'});      
    }      
  }
}

#allow a user to unfollow/leave a user by kicking them from the channel
sub irc_kick {
  my ($kernel, $heap, $data) = @_[KERNEL, HEAP, ARG0];

  my $chan = $data->{'params'}[0];  
  my $target = $data->{'params'}[1];

  if (!$heap->{'channels'}->{$chan}->{'joined'}) {
    $kernel->yield('server_reply',442,$chan,"You're not on that channel");
    return;
  }

  # case insensitive kicks, returns correct hash key so kick/delete works right
  my @matches = grep { m/^$target$/i } keys %{$heap->{'channels'}->{$chan}->{'names'}};
  unless (scalar(@matches) == 1) {
    $kernel->yield('server_reply',441,$target,$chan,"They aren't on that channel");
    return;
  }

  my ($kickee) = @matches;
  
  if ($chan ne '#twitter') {
    delete $heap->{'channels'}->{$chan}->{'names'}->{$kickee};
    $kernel->yield('user_msg','KICK',$heap->{'username'},$chan,$kickee,$kickee);
    return;
  }
  
  my $result = eval { $heap->{'twitter'}->destroy_friend({screen_name => $kickee}) };
  my $error = $@;
  if ($result) {
    $kernel->call($_[SESSION],'remfriend',$kickee);
    delete $heap->{'channels'}->{$chan}->{'names'}->{$kickee};
    $kernel->yield('user_msg','KICK',$heap->{'username'},$chan,$kickee,$kickee);
    $kernel->post('logger','log',"Stopped following $kickee",$heap->{'username'});
  } else {
    if (ref $error && $error->isa("Net::Twitter::Lite::Error") && $error->code() >= 400) {
      $kernel->call($_[SESSION],'twitter_api_error','Unable to unfollow user.',$error);    
    } else {
      $kernel->yield('server_reply',441,$kickee,$chan,"They aren't on that channel");  
      $kernel->post('logger','log',"Attempted to unfollow user ($kickee) we weren't following",$heap->{'username'});
    }
  }  

}

sub irc_ping {
  my ($kernel, $heap, $data) = @_[KERNEL, HEAP, ARG0];
  my $target = $data->{'params'}[0];

  # Olatho - Issue #42 http://code.google.com/p/tircd/issues/detail?id=42  
  $kernel->yield('server_reply','PONG','tircd ' . $target);
}

sub irc_away {
  my ($kernel, $heap, $data) = @_[KERNEL, HEAP, ARG0];
  
  if ($data->{'params'}[0]) {
    $kernel->yield('server_reply',306,'You have been marked as being away');
  } else {
    $kernel->yield('server_reply',305,'You are no longer marked as being away');  
  }
}

sub irc_topic {
  my ($kernel, $heap, $data) = @_[KERNEL, HEAP, ARG0];
  my $chan = $data->{'params'}[0];
  my $topic = $data->{'params'}[1];
  
  return if $chan eq '#twitter';

  if (!$heap->{'channels'}->{$chan}->{'joined'}) {
    $kernel->yield('server_reply',442,$chan,"You're not on that channel");
    return;
  }
  
  $heap->{'channels'}->{$chan}->{'topic'} = $topic;
  $heap->{'channels'}->{$chan}->{'search_since_id'} = 0;

  $kernel->yield('user_msg','TOPIC',$heap->{'username'},$chan,$topic);  
  $kernel->yield('twitter_search',$chan);  
}

#shutdown the socket when the user quits
sub irc_quit {
  my ($kernel, $heap, $data) = @_[KERNEL, HEAP, ARG0];
  $kernel->yield('shutdown');
}

########### IRC 'SPECIAL CHANNELS'

sub channel_twitter {
  my ($kernel,$heap,$chan) = @_[KERNEL, HEAP, ARG0];

  #add our channel to the list  
  $heap->{'channels'}->{$chan} = {};
  $heap->{'channels'}->{$chan}->{'joined'} = 1;

  #get list of friends
  my @friends = ();
  my $cursor = -1;
  my $error;
  while (my $f = eval { $heap->{'twitter'}->friends({'cursor' => $cursor})}) {
    $cursor = $f->{'next_cursor'};
    foreach my $user ($f->{'users'}) {
      foreach my $u (@{$user}) {
        push(@friends, $u);
      }
    }
    last if $cursor == 0;
  }
  my $error = $@;

  #if we have no data, there was an error, or the user is a loser with no friends, eject 'em
  if ($cursor == -1 && ref $error && $error->isa("Net::Twitter::Lite::Error") && $error->code() >= 400) {
    $kernel->call($_[SESSION],'twitter_api_error','Unable to get friends list.',$error);
    return;
  } 

  #get list of followers
  my @followers = ();
  $cursor = -1;
  while (my $f = eval { $heap->{'twitter'}->followers({'cursor' => $cursor}) }) {
    $cursor = $f->{'next_cursor'};
    foreach my $user ($f->{'users'}) {
      foreach my $u (@{$user}) {
        push(@followers, $u);
      }
    }
    last if $cursor == 0;
  }
  $error = $@;

  #alert this error, but don't end 'em
  if ($cursor == -1 && ref $error && $error->isa("Net::Twitter::Lite::Error") && $error->code() >= 400) {
    $kernel->call($_[SESSION],'twitter_api_error','Unable to get followers list.',$error);
  } 

  #cache our friends and followers
  $heap->{'friends'} = \@friends;
  $heap->{'followers'} = \@followers;
  $kernel->post('logger','log','Received friends list from Twitter, caching '.@{$heap->{'friends'}}.' friends.',$heap->{'username'});
  $kernel->post('logger','log','Received followers list from Twitter, caching '.@{$heap->{'followers'}}.' followers.',$heap->{'username'});

  #spoof the channel join
  $kernel->yield('user_msg','JOIN',$heap->{'username'},$chan);	
  $kernel->yield('server_reply',332,$chan,"$heap->{'username'}'s twitter");
  $kernel->yield('server_reply',333,$chan,'tircd!tircd@tircd',time());
  
  #the the list of our users for /NAMES
  my $lastmsg = '';
  foreach my $user (@{$heap->{'friends'}}) {
    my $ov ='';
    if ($user->{'screen_name'} eq $heap->{'username'}) {
      $lastmsg = $user->{'status'}->{'text'};
      $ov = '@';
    } elsif ($kernel->call($_[SESSION],'getfollower',$user->{'screen_name'})) {
      $ov='+';
    }
    #keep a copy of who is in this channel
    $heap->{'channels'}->{$chan}->{'names'}->{$user->{'screen_name'}} = $ov;
  }

  # Add the tircdbot
  $heap->{'channels'}->{$chan}->{'names'}->{'tircdbot'} = '%';
  
  if (!$lastmsg) { #if we aren't already in the list, add us to the list for NAMES - AND go grab one tweet to put us in the array
    $heap->{'channels'}->{$chan}->{'names'}->{$heap->{'username'}} = '@';
    my $data = eval { $heap->{'twitter'}->user_timeline({count => 1}) };
    if ($data && @$data > 0) {
      $kernel->post('logger','log','Received user timeline from Twitter.',$heap->{'username'});
      my $tmp = $$data[0]->{'user'};
      $tmp->{'status'} = $$data[0];
      $lastmsg = $tmp->{'status'}->{'text'};
      push(@{$heap->{'friends'}},$tmp);
    }
  }  

  #send the /NAMES info
  my $all_users = '';
  foreach my $name (keys %{$heap->{'channels'}->{$chan}->{'names'}}) {
    $all_users .= $heap->{'channels'}->{$chan}->{'names'}->{$name} . $name .' ';
  }
  $kernel->yield('server_reply',353,'=',$chan,$all_users);
  $kernel->yield('server_reply',366,$chan,'End of /NAMES list');

  $kernel->yield('user_msg','TOPIC',$heap->{'username'},$chan,"$heap->{'username'}'s last update: $lastmsg");

  #start our twitter even loop, grab the timeline, replies and direct messages
  $kernel->yield('twitter_timeline', $heap->{'config'}->{'join_silent'});
  $kernel->yield('twitter_direct_messages', $heap->{'config'}->{'join_silent'});
  
  return 1;
}

########### TWITTER EVENT/ALARM FUNCTIONS

sub twitter_timeline {
  my ($kernel, $heap, $silent) = @_[KERNEL, HEAP, ARG0];

  #get updated messages
  my ($timeline, $error);

  my %timeline_request = (
    count => $heap->{'config'}->{'timeline_count'},
    include_entities => 1,
  );

  if ($heap->{'timeline_since_id'}) {
    $timeline_request{'since_id'} = $heap->{'timeline_since_id'};
  }

  $timeline = eval { $heap->{'twitter'}->home_timeline(\%timeline_request) };
  $error = $@;

  #sometimes the twitter API returns undef, so we gotta check here
  if (!$timeline || @$timeline == 0 || @{$timeline}[0]->{'id'} < $heap->{'timeline_since_id'} ) {
    $timeline = [];
    if (ref $error && $error->isa("Net::Twitter::Lite::Error") && $error->code() >= 400) {
      $kernel->call($_[SESSION],'twitter_api_error','Unable to update timeline.',$error);   
    }
  } else {
    #if we got new data save our position
    $heap->{'timeline_since_id'} = @{$timeline}[0]->{'id'};
    $kernel->post('logger','log','Received '.@$timeline.' timeline updates from Twitter.',$heap->{'username'});
  }

  #get updated @replies too
  my $replies;
  if ($heap->{'replies_since_id'}) {
    $replies = eval { $heap->{'twitter'}->replies({since_id => $heap->{'replies_since_id'}, include_entities => 1}) };
    $error = $@;
  } else {
    $replies = eval { $heap->{'twitter'}->replies({page =>1, include_entities => 1}) }; #avoid a bug in Net::Twitter
    $error = $@;
  }

  if (!$replies || @$replies == 0) {
    $replies = [];
    if (ref $error && $error->isa("Net::Twitter::Lite::Error") && $error->code() >= 400) {
      $kernel->call($_[SESSION],'twitter_api_error','Unable to update @replies.',$error);   
    }
  } else {  
    $heap->{'replies_since_id'} = @{$replies}[0]->{'id'};
    $kernel->post('logger','log','Received '.@$replies.' @replies from Twitter.',$heap->{'username'});
  }
  
  #weave the two arrays together into one stream, removing duplicates
  my @tmpdata = (@{$timeline},@{$replies});
  my %tmphash = ();
  foreach my $item (@tmpdata) {
    $tmphash{$item->{'id'}} = $item;
  }

  #loop through each message
  foreach my $item (sort {$a->{'id'} <=> $b->{'id'}} values %tmphash) {
    my $tmp = $item->{'user'};
    my $is_following = ();
    $tmp->{'status'} = $item;

    # Replace URLS and expand Real Names 
    # This is quite ugly, but it's the best I could do...
    # Ignore it for my own messages 

    if (lc($item->{'user'}->{'screen_name'}) ne lc($heap->{'username'})) {
      if ($heap->{'config'}->{'expand_urls'}==1 && defined($item->{'entities'}->{'urls'})) {
        foreach my $url (@{$item->{'entities'}->{'urls'}}) {
          if (defined($url->{'expanded_url'})) {
            $kernel->post('logger','log','Replacing URL ' . $url->{'url'} . ' with ' . $url->{'expanded_url'},$heap->{'username'}) if ($config{'debug'} >= 2);
            my $search = $url->{'url'};
            my $replace = $url->{'expanded_url'};
            $item->{'text'} =~ s/$search/$replace/g;
            # Also replace text in retweets
            if(defined($item->{'retweeted_status'})) {
               $item->{'retweeted_status'}->{'text'} =~ s/$search/$replace/g;
            }
          }
       }
    }
       
       if ($heap->{'config'}->{'show_realname'} == 1 && defined($item->{'entities'}->{'user_mentions'})) {
          foreach my $user (@{$item->{'entities'}->{'user_mentions'}}) {
             $kernel->post('logger','log','Showing realname ' . $user->{'name'} . ' for ' . $user->{'screen_name'},$heap->{'username'}) if ($config{'debug'} >= 2);
             my $search  = "@" . $user->{'screen_name'};
             my $replace = "@" . $user->{'screen_name'} . " (" . $user->{'name'} . ")";

             $item->{'text'} =~ s/$search/$replace/g;

             # Also replace text in retweets
             if(defined($item->{'retweeted_status'})) {
                $item->{'retweeted_status'}->{'text'} =~ s/$search/$replace/ig;

                if ($user->{'screen_name'} eq $item->{'retweeted_status'}->{'user'}->{'screen_name'}) {
                     # If the text does not contain the username of the person being retweeted
                     # also add realname first in text
                   if ($item->{'retweeted_status'}->{'text'} !~ /$item->{'retweeted_status'}->{'user'}->{'screen_name'}/) {
                      my $search  = "^";
                      my $replace = "(" . $user->{'name'} . ") ";
                      $item->{'retweeted_status'}->{'text'} =~ s/$search/$replace/ig;
                   }
                }
             }
          }
       }
    }

    # assign a ticker slot for later referencing with !reply or !retweet
    my $ticker_slot = get_timeline_ticker_slot();
    $heap->{'timeline_ticker'}->{$ticker_slot} = $item->{'id'};
    $item->{'tircd_ticker_slot'} = $ticker_slot;
    $item->{'tircd_ticker_slot_display'} = ($heap->{'config'}->{'display_ticker_slots'}) ? '[' . $ticker_slot . '] ' : '';
    $kernel->post('logger','log','Slot ' . $ticker_slot . ' now contains tweet with id: ' . $item->{'id'},$heap->{'username'}) if ($config{'debug'} >= 2);
    
    if (my $friend = $kernel->call($_[SESSION],'getfriend',$item->{'user'}->{'screen_name'})) { #if we've seen 'em before just update our cache
      $kernel->call($_[SESSION],'updatefriend',$tmp);
    } else { 
      # removed the fake join tempoarily while, I figure out the better way to handle this.  I think the best is to leave it like this and treat the channels as if they are -n
      # Olatho - Re enabled this - fixes the bug where you do not see tweets from people you add from other clients.
      # But there is a problem here.
      # If you are not following the user, and they mention you, they are joining the channel, and you can't /invite later..
      # Adding a fake part again imediately if they are not a friend, to make it clear what happens
      # Also, only adding them to 'friends' if they really are friends

      $kernel->post('logger','log','Getting userinfo for ' . $item->{'user'}->{'screen_name'},$heap->{'username'}) if $config{'debug'} >=2;
      $is_following = eval { $heap->{'twitter'}->show_user({screen_name => $item->{'user'}->{'screen_name'}}) };
      $kernel->post('logger','log','Got name: ' . $is_following->{'name'} . ' following: ' . $is_following->{'following'}, $heap->{'username'}) if $config{'debug'} >=2;
      if ($is_following->{'following'} == 1) {
	# We are following this user, add to 'friends'
        push(@{$heap->{'friends'}},$tmp);
      }
      # Join them to #twitter if they are not yourself
      if (lc($item->{'user'}->{'screen_name'}) ne lc($heap->{'username'})) {
        $kernel->yield('user_msg','JOIN',$item->{'user'}->{'screen_name'},'#twitter') unless ($silent);
        # Check if they should have voice (+v)
        if ($kernel->call($_[SESSION],'getfollower',$item->{'user'}->{'screen_name'})) {
          $heap->{'channels'}->{'#twitter'}->{'names'}->{$item->{'user'}->{'screen_name'}} = '+';
          $kernel->yield('server_reply','MODE','#twitter','+v',$item->{'user'}->{'screen_name'});
        } else {
          $heap->{'channels'}->{'#twitter'}->{'names'}->{$item->{'user'}->{'screen_name'}} = '';
        }
      }
    }
    
    # filter out our own messages / don't display if not in silent mode
    # Olatho - Don't understand what the original code tried to do, but my changes tries to do the right thing
    # This will lead to seeing messages twice if you are tweeting actively, as messages are parsed both when you tweet, and when tircd receives the updates
    # But I prefer that instead of missing messages I add from other clients
    # This can be fixed by using a global buffer/cache to filter out the messages, not just the latest topic
    if ((lc($item->{'user'}->{'screen_name'}) ne lc($heap->{'username'}) || !$heap->{'config'}->{'filter_self'})) {
      if (!$silent) {
        foreach my $chan (keys %{$heap->{'channels'}}) {
          # - Send the message to the #twitter-channel if it is different from my latest update (IE different from current topic)
          if ($chan eq '#twitter' && exists $heap->{'channels'}->{$chan}->{'names'}->{$item->{'user'}->{'screen_name'}} && $item->{'text'} ne $heap->{'channels'}->{$chan}->{'topic'}) {
            # TODO clean this logic block
            # TODO change filtering for realname / urls to happen here, along with general filtering
            # Fixing issue #81
            if(defined($item->{'retweeted_status'})) {
              $kernel->yield('user_msg','PRIVMSG',$item->{'user'}->{'screen_name'},$chan,$item->{'tircd_ticker_slot_display'} . 'RT @' . $item->{'retweeted_status'}->{'user'}->{'screen_name'} . ': ' . $item->{'retweeted_status'}->{'text'});
            }
            else {
              $kernel->yield('user_msg','PRIVMSG',$item->{'user'}->{'screen_name'},$chan,$item->{'tircd_ticker_slot_display'} . $item->{'text'});
            }
          }
          # - Send the message to the other channels the user is in if the user is not "me"
          if ($chan ne '#twitter' && exists $heap->{'channels'}->{$chan}->{'names'}->{$item->{'user'}->{'screen_name'}} && $item->{'user'}->{'screen_name'} ne $heap->{'username'}) {
            $kernel->yield('user_msg','PRIVMSG',$item->{'user'}->{'screen_name'},$chan,$item->{'tircd_ticker_slot_display'} . $item->{'text'});
          }
          # - And set topic on the #twitter channel if user is me and the topic is not already set 
          if ($chan eq '#twitter' && $item->{'user'}->{'screen_name'} eq $heap->{'username'} && $item->{'text'} ne $heap->{'channels'}->{$chan}->{'topic'}) {
            $kernel->yield('user_msg','TOPIC',$heap->{'username'},$chan,"$heap->{'username'}'s last update: ".$item->{'text'});
            $heap->{'channels'}->{$chan}->{'topic'} = $item->{'text'};
          }            
        }          
      }        
    }
    #TODO easier way to judge self?
    if (lc($item->{'user'}->{'screen_name'}) ne lc($heap->{'username'})) {
      if (($is_following->{'status'}) && ($is_following->{'following'} == 0)) {
        # If we are not following them - have them part #twitter again
        $kernel->yield('user_msg','PART',$item->{'user'}->{'screen_name'},'#twitter') unless ($silent);
        delete $heap->{'channels'}->{'#twitter'}->{'names'}->{$item->{'user'}->{'screen_name'}};
      }
    }
  }

  if ($heap->{'config'}->{'update_timeline'} > 0) {
    $kernel->delay('twitter_timeline',$heap->{'config'}->{'update_timeline'});
  }
}

#same as above, but for direct messages, show 'em as PRIVMSGs from the user
sub twitter_direct_messages {
  my ($kernel, $heap, $silent) = @_[KERNEL, HEAP, ARG0];

  my $data;
  my $error;
  if ($heap->{'direct_since_id'}) {
    $data = eval { $heap->{'twitter'}->direct_messages({since_id => $heap->{'direct_since_id'}, include_entities => 1}) };
    $error = $@;
  } else {
    $data = eval { $heap->{'twitter'}->direct_messages({include_entities => 1}) };
    $error = $@;
  }

  if (!$data || @$data == 0 || @{$data}[0]->{'id'} < $heap->{'direct_since_id'}) {
    $data = [];
    if (ref $error && $error->isa("Net::Twitter::Lite::Error") && $error->code() >= 400) {
      $kernel->call($_[SESSION],'twitter_api_error','Unable to update direct messages.',$error);   
    }
  } else {
    $heap->{'direct_since_id'} = @{$data}[0]->{'id'};
    $kernel->post('logger','log','Received '.@$data.' direct messages from Twitter.',$heap->{'username'});
  }

  foreach my $item (sort {$a->{'id'} <=> $b->{'id'}} @{$data}) {
    # Do not join #twitter if it is me
    if (lc($item->{'sender'}->{'screen_name'}) ne lc($heap->{'username'})) {
      if (!$kernel->call($_[SESSION],'getfriend',$item->{'sender'}->{'screen_name'})) {
        my $tmp = $item->{'sender'};
        $tmp->{'status'} = $item;
        $tmp->{'status'}->{'text'} = '(dm) '.$tmp->{'status'}->{'text'};
        push(@{$heap->{'friends'}},$tmp);
        $kernel->yield('user_msg','JOIN',$item->{'sender'}->{'screen_name'},'#twitter');
        if ($kernel->call($_[SESSION],'getfollower',$item->{'user'}->{'screen_name'})) {
          $heap->{'channels'}->{'#twitter'}->{'names'}->{$item->{'user'}->{'screen_name'}} = '+';
          $kernel->yield('server_reply','MODE','#twiter','+v',$item->{'user'}->{'screen_name'});        
        } else {
          $heap->{'channels'}->{'#twitter'}->{'names'}->{$item->{'user'}->{'screen_name'}} = '';
        }
      }
    }
    
    if (!$silent) {
      $kernel->yield('user_msg','PRIVMSG',$item->{'sender'}->{'screen_name'},$heap->{'username'},$item->{'text'});
    }      
  }
  if ($heap->{'config'}->{'update_directs'} > 0) {
    $kernel->delay('twitter_direct_messages',$heap->{'config'}->{'update_directs'});
  }
}

# reusable timeline ticker. 
# ticker names as short hashes for readability/uniqueness
# does ~3800 tweets before rebuilding list
sub get_timeline_ticker_slot {
   my ($kernel, $heap) = @_[KERNEL, HEAP];

   # build usage order list
   if (!defined($heap->{'timeline_ticker_unused'}) || (scalar($heap->{'timeline_ticker_unused'}) < 1)) {
      push (@{$heap->{'timeline_ticker_unused'}},  sprintf("%x", $_)) for (shuffle(256 .. 4095));
   }

   my $ticker_slot = pop(@{$heap->{'timeline_ticker_unused'}});

   return $ticker_slot;
}




sub twitter_search {
  my ($kernel, $heap, $chan) = @_[KERNEL, HEAP, ARG0];

  if (!$heap->{'channels'}->{$chan}->{'joined'} || !$heap->{'channels'}->{$chan}->{'topic'}) {
    #if we aren't in the channel, don't do anything, this will keep us from restarting timers for channels we are no longer in
    return;
  }
  
  my $data;
  my $error;
  if ($heap->{'channels'}->{$chan}->{'search_since_id'}) {
    $data = eval {$heap->{'twitter'}->search({q => $heap->{'channels'}->{$chan}->{'topic'}, rpp => 100, since_id => $heap->{'channels'}->{$chan}->{'search_since_id'}, include_entities => 1});};
    $error = $@;
  } else {   
    $data = eval {$heap->{'twitter'}->search({q => $heap->{'channels'}->{$chan}->{'topic'}, rpp => 100, include_entities => 1});};
    $error = $@;
  }

  my $delay = 30;

  if (!$data || $data->{'search_metadata'}->{'max_id'} < $heap->{'channels'}->{$chan}->{'search_since_id'} ) {
    $data = {results => []};
    $kernel->call($_[SESSION],'twitter_api_error','Unable to update search results.',$error);   
    if ($error) {
      if ($error->code() == 420) {
        # We are ratelimited
        $delay = 400;
        $kernel->post('logger','log','We are ratelimited, waiting for '. $delay .' seconds before repeating search',$heap->{'username'});
      }
    }

  } else {
    $heap->{'channels'}->{$chan}->{'search_since_id'} = $data->{'search_metadata'}->{'max_id'};
    if (@{$data->{'statuses'}} > 0) {
      $kernel->post('logger','log','Received '.@{$data->{'statuses'}}.' search results from Twitter.',$heap->{'username'});
    }      
  }

  foreach my $result (sort {$a->{'id'} <=> $b->{'id'}} @{$data->{'statuses'}}) {
    ### Search API does not support entities yet. 
    #   When that happens we should either copy the code from timeline to expand urls and realname
    #   Or we should split that out as a function 
    #   /Olatho
    if ($result->{'user'}->{'screen_name'} ne $heap->{'username'}) {
      $kernel->yield('user_msg','PRIVMSG',$result->{'user'}->{'screen_name'},$chan,$result->{'text'});
    }
  }

  $kernel->delay_add('twitter_search',$delay,$chan);    
}

sub tircd_get_message_parts {
    # only take target to direct error strings
    my ($kernel, $heap, $target, $msg) = @_[KERNEL, HEAP, ARG0, ARG1];

    my @parts = undef;

    if (length($msg) <= 140) {
        @parts = ($msg);
    }    

    if (length($msg) > 140) {
        if ($heap->{'config'}->{'long_messages'} eq 'warn') {
            $kernel->yield('server_reply',404,$target,'Your message is '.length($msg).' characters long.  Your message was not sent.');
            return;
        }  

        if ($heap->{'config'}->{'long_messages'} eq 'split') {
            @parts = $msg =~ /(.{1,140}\b)/g;
            if (scalar(@parts) > $heap->{'config'}->{'max_splits'}) {
                $kernel->yield('server_reply',404,$target,"The last message would split into " . scalar(@parts) . " tweets. This is greater than the number allowe by your max_splits setting.");
                return;
            }
            if (length($parts[$#parts]) < $heap->{'config'}->{'min_length'}) {
                $kernel->yield('server_reply',404,$target,"The last of the split messages would only be ".length($parts[$#parts]).' characters long.  Your message was not sent.');
                return;
            }
        }
    }

    $kernel->post('logger','log','Got '.length($msg).' char message of: '.$msg.' ### turned it in to '.scalar(@parts).' chunks',$heap->{'username'});
    return @parts;
}
    
sub twitter_conversation {
  # TODO - store the complete conversation in a temp-variable, 
  # revere it and display it in the proper order
  my($kernel, $heap, $tweet_id) = @_[KERNEL, HEAP, ARG0];
  $kernel->post('logger','log','Getting conversation from status: '. $tweet_id);
  my $status = eval { $heap->{'twitter'}->show_status($tweet_id) };
  my $error = $@;
  if ($error) {
    $kernel->call($_[SESSION],'twitter_api_error','Unable to get post.',$error);   
    return;
  }
  my $chan = '#twitter';
  if ($status->{'in_reply_to_status_id'}) {
    $kernel->yield('server_reply',304,'Conversation for ' . $tweet_id);
    $kernel->yield('user_msg','PRIVMSG',$status->{'user'}->{'screen_name'},$chan, "[" . $status->{'created_at'} . "] " . $status->{'text'});
    $kernel->yield('twitter_conversation_r', $status->{'in_reply_to_status_id'});
  }
  else {
    $kernel->post('logger','log','No in_reply_to - trying to get related posts instead');
    $kernel->yield('twitter_conversation_related', $tweet_id);
  }      
}

sub twitter_conversation_related {
  my($kernel, $heap, $tweet_id) = @_[KERNEL, HEAP, ARG0];
  $kernel->post('logger','log','related api no longer supported');
  return;

  $kernel->post('logger','log','Getting related from status: '. $tweet_id);
  my $related = eval { $heap->{'twitter'}->related_results($tweet_id) };
  my $error = $@;
  if ($error) {
    $kernel->call($_[SESSION],'twitter_api_error','Unable to get related posts.',$error);   
  }
  my $chan = '#twitter';
  if ((@{$related}[0]) && (@{@{$related}[0]->{'results'}} > 0)) {
    $kernel->yield('server_reply',304,'Related posts for ' . $tweet_id);
    foreach my $result (@{@{$related}[0]->{'results'}}) {
      $kernel->yield('user_msg','PRIVMSG',$result->{'value'}->{'user'}->{'screen_name'},$chan, "[" . $result->{'value'}->{'created_at'} . "] " . $result->{'value'}->{'text'});
    }
    $kernel->yield('server_reply',304,'End of related posts');
  }
  else {
    $kernel->yield('server_reply',404,'Cannot find related posts for ' . $tweet_id);
  }      
}


sub twitter_conversation_r {
  my($kernel, $heap, $tweet_id) = @_[KERNEL, HEAP, ARG0];
  my $status = eval { $heap->{'twitter'}->show_status($tweet_id) };
  my $error = $@;
  if ($error) {
    $kernel->call($_[SESSION],'twitter_api_error','Unable to get post.',$error);   
    return;
  }
  my $chan = '#twitter';
  if ($status->{'text'}) {
    $kernel->yield('user_msg','PRIVMSG',$status->{'user'}->{'screen_name'},$chan, "[" . $status->{'created_at'} . "] " . $status->{'text'});
  }
  if ($status->{'in_reply_to_status_id'}) {
    $kernel->yield('twitter_conversation_r', $status->{'in_reply_to_status_id'});
  }
  else {
    $kernel->yield('server_reply',304,'End of conversation');
  }

}


__END__

=head1 Documentation moved

Please see tircd.pod which should have been included with this script
