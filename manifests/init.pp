# == Class: rsyslog
#
# Set up rsyslogd
#
# It is assumed that local6 will be used for all logs collected from files.
#
# You will need to add a rule specifically for this if you want to send them to
# a remote host.
#
# == Parameters
#
# [*enable_default_rules*]
# Type: Boolean
# Default: true
#   If true, add a set of reasonable output rules to the system targeted at
#   local files.
#
# [*include_rsyslog_d*]
#  Type: Boolean
#  Default: false
#   If true, then all .conf files inside of /etc/rsyslog.d will be included.
#
# [*purge_old_rules*]
# Type: Boolean
# Default: true
#   If true, remove all unmanaged rules in /etc/rsyslog.d/puppet_managed.
#
# == Authors
#
# * Trevor Vaughan <mailto:tvaughan@onyxpoint.com>
#
class rsyslog 
{
  include 'logrotate'
  include 'rsyslog::install'
  include 'rsyslog::config'
  include 'rsyslog::service'

  if $::use_iptables or hiera('use_iptables') {
    include 'rsyslog::firewall'
    Class['::rsyslog::service'] ->
    Class['::rsyslog::firewall']
  }

  Class['::rsyslog::install'] ~>
  Class['::rsyslog::config'] ~>
  Class['::rsyslog::service']
}
