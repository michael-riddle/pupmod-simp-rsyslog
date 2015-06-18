# == Class: rsyslog::config
#
# Setup the global section of /etc/rsyslog.conf.
#
# == Parameters
#
# Almost all of the variables come directly from rsyslog. The ones
# that do not, or have unusual behavior, are noted here.
#
# [*mainMsgQueueSize*]
#   Type: Integer
#   Default: The minimum of 1% of physical memory or 1G, based on a 512B message size.
#     The maximum number of messages that may be stored in the memory queue.
#
# [*mainMsgQueueHighWatermark*]
#   Type: Integer
#   Default: 98% of $mainMsgQueueSize
#     The point at which the queue will start writing messages to disk
#     as a number of messages.
#
# [*mainMsgQueueLowWatermark*]
#   Type: Integer
#   Default: 70% of $mainMsgQueueSize
#     The point at which the queue will stop writing messages to disk
#     as a number of messages.
#
#     This must be *lower* than _mainMsgQueueHighWaterMark_
#
# [*mainMsgQueueDiscardmark*]
#   Type: Integer
#   Default: 2X of $mainMsgQueueSize
#   The point at which the queue will discard messages.
#
# [*mainMsgQueueWorkerThreadMinimumMessages*]
#   Type: Integer
#   Default: ''
#     The minimum number of messages in the queue before a new thread
#     can be spawned.
#
#     If left empty (the default), will calculate the value based on
#     the following formula:
#       $mainMsgQueueSize/(($processorcount - 1)*4)
#
# [*mainMsgQueueWorkerThreads*]
#   Type: Integer
#   Default: ''
#     The maximum number of threads to spawn on the system. Defaults
#     to $processorcount - 1.
#
# [*mainMsgQueueMaxDiskSpace*]
#   Type: Integer
#   Default: ''
#     The maximum amount of disk space to use for the disk queue.
#     Specified as a digit followed by a unit specifier. For example:
#       100   -> 100 Bytes
#       100K  -> 100 Kilobytes
#       100M  -> 100 Megabytes
#       100G  -> 100 Gigabytes
#       100T  -> 100 Terabytes
#       100P  -> 100 Petabytes
#     If not specified, will default to ($mainMsgQueueSize * 1024)
#
# [*mainMsgQueueMaxFileSize*]
#   Type: Integer
#   Default: '5'
#     The maximum file size, in Megabytes, that should be created when
#     buffering to disk. It is not recommended to make this
#     excessively large.
#
#
# [*defaultTemplate*]
#   The default template to use to output to various services. This one has
#   been designed to work with external parsing tools that require the
#   priority text.
#
#   You can also choose from the following values in order to select from one
#   of the built-in rsyslogd formats.
#     * forward     -> RSYSLOG_Forward
#     * original    -> RSYSLOG_FileFormat
#     * traditional -> RSYSLOG_TraditionalFileFormat
#
# [*interval*]
#     The mark interval.
#
# [*tcpserver*]
#     Set to true if the system is a syslog server.
#
# [*tcpServerRun*]
#     Type: Port
#     Default: '514'
#       The port upon which to listen for unencrypted TCP connections.
#
# [*use_tls*]
#   Type: Boolean
#   Default: true
#     If true, use TLS for TCP connections by default.
#
# [*tls_tcpserver*]
#   Type: Boolean
#   Default: false
#     If true, run an encrypted TCP listener.
#
# [*tls_tcpMaxSessions*]
#     The maximum number of sessions to support. 200 is default.
#
# [*tls_tcpServerRun*]
#   Type: Port
#   Default: '6514'
#     If _$tls_tcpserver_ is true, designates the port upon which to
#     listen for incoming encrypted sessions. The port should not be
#     changed if you are using SELinux.
#
# [*use_simp_pki*]
#   Type: Boolean
#   Default: true
#     If true, use the SIMP 'pki' module to provide system
#     certificates.
#
# [*cert_source*]
#   Type: Absolute Path
#   Default: ''
#     If _$use_simp_pki_ is false, then pull all certificates from
#     this valid Puppet File resource source. They should be in the
#     same format as expected from the SIMP PKI structure.
#     Example Layout:
#       private/<fqdn>.pem
#       public/<fqdn>.pub
#       cacerts/cacerts.pem <- All CA certificates go here!
#
# [*umask*]
#   The umask that should be applied to the running process.
#
# [*ulimit_max_open_files*]
#   The ulimit that should be set for the syslog server.
#   1024 is fine for most purposes, but a collection server should bump this
#   *way* up.
#
# [*compat_mode*]
#   Sysconfig option to note what compatibility mode rsyslog is running in.
#   See the -c option in rsyslogd(8) for more information.
#
# [*hostlist*]
#   Sysconfig Option
#   Array of hosts to be logged with their simple hostname.
#   See the -l option in rsyslogd(8) for more information.
#
# [*domainlist*]
#     Sysconfig Option
#     Array of domains that should be stripped off before logging.
#     See the -s option in rsyslogd(8) for more information.
#
# [*suppress_noauth_warn*]
#   Sysconfig Option
#   Set to someting other than false to suppress warnings due to hosts not in
#   the ACL.
#   See the -w option in rsyslogd(8) for more information.
#
# [*disable_remote_dns*]
#   Sysconfig Option
#   Disable DNS for remote messages.
#   See the -x option in rsyslogd(8) for more information.
#
# [*allow_failover*]
#   Type: Boolean
#   Default: false
#   Enables failover to other log_servers listed in the log_servers variable in
#   hiera. Before setting this to true, ensure you have more than one
#   log_server listed in the hiera variable.  
#
# == Authors
#
# * Mike Riddle <mailto:mriddle@onyxpoint.com>
# * Kendall Moore <mailto:kmoore@keywcorp.com>
# * Trevor Vaughan <mailto:tvaughan@onyxpoint.com>
#
class rsyslog::config(
  $preserveFQDN                                 = $::rsyslog::params::preserveFQDN,
  $system_log_rate_limit_interval               = $::rsyslog::params::system_log_rate_limit_interval,
  $system_log_rate_limit_burst                  = $::rsyslog::params::system_log_rate_limit_burst,
  $mainMsgQueueType                             = $::rsyslog::params::mainMsgQueueType,
  $mainMsgQueueFilename                         = $::rsyslog::params::mainMsgQueueFilename,
  $mainMsgQueueMaxFileSize                      = $::rsyslog::params::mainMsgQueueMaxFileSize,
  $mainMsgQueueSize                             = $::rsyslog::params::mainMsgQueueSize,
  $mainMsgQueueHighWatermark                    = $::rsyslog::params::mainMsgQueueHighWatermark,
  $mainMsgQueueLowWatermark                     = $::rsyslog::params::mainMsgQueueLowWatermark,
  $mainMsgQueueDiscardmark                      = $::rsyslog::params::mainMsgQueueDiscardmark,
  $mainMsgQueueWorkerThreadMinimumMessages      = $::rsyslog::params::mainMsgQueueWorkerThreadMinimumMessages,
  $mainMsgQueueWorkerThreads                    = $::rsyslog::params::mainMsgQueueWorkerThreads,
  $mainMsgQueueWorkerTimeoutThreadShutdown      = $::rsyslog::params::mainMsgQueueWorkerTimeoutThreadShutdown,
  $mainMsgQueueTimeoutEnqueue                   = $::rsyslog::params::mainMsgQueueTimeoutEnqueue,
  $mainMsgQueueDequeueSlowdown                  = $::rsyslog::params::mainMsgQueueDequeueSlowdown,
  $mainMsgQueueSaveOnShutdown                   = $::rsyslog::params::mainMsgQueueSaveOnShutdown,
  $mainMsgQueueMaxDiskSpace                     = $::rsyslog::params::mainMsgQueueMaxDiskSpace,
  $actionResumeInterval                         = $::rsyslog::params::actionResumeInterval,
  $actionResumeRetryCount                       = $::rsyslog::params::actionResumeRetryCount,
  $tcpAllowedSender                             = $::rsyslog::params::tcpAllowedSender,
  $controlCharacterEscapePrefix                 = $::rsyslog::params::controlCharacterEscapePrefix,
  $defaultTemplate                              = $::rsyslog::params::defaultTemplate,
  $dirCreateMode                                = $::rsyslog::params::dirCreateMode,
  $dirGroup                                     = $::rsyslog::params::dirGroup,
  $dirOwner                                     = $::rsyslog::params::dirOwner,
  $dropMsgsWithMaliciousDnsPTRRecords           = $::rsyslog::params::dropMsgsWithMaliciousDnsPTRRecords,
  $escapeControlCharactersOnReceive             = $::rsyslog::params::escapeControlCharactersOnReceive,
  $fileCreateMode                               = $::rsyslog::params::fileCreateMode,
  $fileGroup                                    = $::rsyslog::params::fileGroup,
  $fileOwner                                    = $::rsyslog::params::fileOwner,
  $include_config                               = $::rsyslog::params::include_config,
  $repeatedMsgReduction                         = $::rsyslog::params::repeatedMsgReduction,
  $workDirectory                                = $::rsyslog::params::workDirectory,
  $interval                                     = $::rsyslog::params::interval,
  $tcpserver                                    = $::rsyslog::params::tcpserver,
  $tcpServerRun                                 = $::rsyslog::params::tcpServerRun,
  $use_tls                                      = $::rsyslog::params::use_tls,
  $tls_tcpserver                                = $::rsyslog::params::tls_tcpserver,
  $tls_tcpServerRun                             = $::rsyslog::params::tls_tcpServerRun,
  $tls_tcpMaxSessions                           = $::rsyslog::params::tls_tcpMaxSessions,
  $tls_inputTCPServerStreamDriverPermittedPeers = $::rsyslog::params::tls_inputTCPServerStreamDriverPermittedPeers,
  $use_simp_pki                                 = $::rsyslog::params::use_simp_pki,
  $cert_source                                  = $::rsyslog::params::cert_source,
  $defaultNetStreamDriverCAFile                 = $::rsyslog::params::defaultNetStreamDriverCAFile,
  $defaultNetStreamDriverCertFile               = $::rsyslog::params::defaultNetStreamDriverCertFile,
  $defaultNetStreamDriverKeyFile                = $::rsyslog::params::defaultNetStreamDriverKeyFile,
  $actionSendStreamDriverPermittedPeers         = $::rsyslog::params::actionSendStreamDriverPermittedPeers,
  $actionSendStreamDriverAuthMode               = $::rsyslog::params::actionSendStreamDriverAuthMode,
  $udpserver                                    = $::rsyslog::params::udpserver,
  $udpServerAddress                             = $::rsyslog::params::udpServerAddress,
  $udpServerRun                                 = $::rsyslog::params::udpServerRun,
  $udpAllowedSender                             = $::rsyslog::params::udpAllowedSender,
  $umask                                        = $::rsyslog::params::umask,
  $ulimit_max_open_files                        = $::rsyslog::params::ulimit_max_open_files,
  $compat_mode                                  = $::rsyslog::params::compat_mode,
  $hostlist                                     = $::rsyslog::params::hostlist,
  $domainlist                                   = $::rsyslog::params::domainlist,
  $suppress_noauth_warn                         = $::rsyslog::params::suppress_noauth_warn,
  $disable_remote_dns                           = $::rsyslog::params::disable_remote_dns,
  $include_rsyslog_d                            = $::rsyslog::params::include_rsyslog_d,
  $enable_default_rules                         = $::rsyslog::params::enable_default_rules,
  $allow_failover                               = $::rsyslog::params::allow_failover
) inherits rsyslog::params {
  include 'tcpwrappers'

  if !($tcpserver or $tls_tcpserver or $udpserver) {
    generic_warning{'shiziznotinstuff':
      ensure => 'present',
      message => 'The shiz is not in the stuff'
    }
  }

  if $allow_failover {
    $secondary_log_servers = hiera_array('log_servers')
    if !empty($secondary_log_servers) and (size($secondary_log_servers) > 1){
      $l_secondary_log_servers = delete_at($secondary_log_servers, 0)
    }

    if ($l_secondary_log_servers == undef or (empty($secondary_log_servers)) and $allow_failover_global) {
      fail("Rsyslog rule $name specified to allow failover when no failover servers have been defined. You must have at least two log servers listed in the log_servers variable in hiera for failover to work properly.")
    }
  }

  $outfile = concat_output('rsyslog')

  concat_build { 'rsyslog_templates':
    order            => '*.template',
    clean_whitespace => leading,
    target           => '/etc/rsyslog.simp.d/05_simp_templates/custom_templates.conf',
    onlyif           =>
      "/usr/bin/test `/usr/bin/wc -w  ${outfile} | /bin/cut -f1 -d' '` -ne 0",
    require          => Package["rsyslog.${::hardwaremodel}"]
  }

  if $enable_default_rules {
    rsyslog::rule::local { 'ZZ_default':
      rule => template('rsyslog/rsyslog.default.erb')
    }
  }

  file { '/etc/rsyslog.simp.d/05_simp_templates/custom_templates.conf':
    ensure    => 'present',
    owner     => 'root',
    group     => 'root',
    mode      => '0600',
    audit     => content,
    notify    => Service['rsyslog'],
    require   => [Package["rsyslog.${::hardwaremodel}"],File['/etc/rsyslog.simp.d/05_simp_templates']],
    subscribe => Concat_build['rsyslog_templates']
  }

  # Set up the initial logrotate rule
  logrotate::add { 'syslog':
    log_files  => [
      '/var/log/messages',
      '/var/log/secure',
      '/var/log/maillog',
      '/var/log/spooler',
      '/var/log/boot.log',
      '/var/log/cron',
      '/var/log/iptables.log',
      '/var/log/puppet*.log'
    ],
    lastaction => '/sbin/service rsyslog restart > /dev/null 2>&1 || true',
    missingok  => true
  }

  file { '/etc/rsyslog.conf':
    ensure  => 'present',
    owner   => 'root',
    group   => 'root',
    mode    => '0600',
    audit   => content,
    content => template('rsyslog/rsyslog.conf.global.erb'),
    notify  => Service['rsyslog'],
    require => Package["rsyslog.${::hardwaremodel}"],
  }

  file { '/etc/sysconfig/rsyslog':
    owner    => 'root',
    group    => 'root',
    mode     => '0644',
    content  => template('rsyslog/sysconfig.erb'),
    notify   => Service['rsyslog']
  }

  file { '/etc/rsyslog.simp.d/00_simp_pre_logging/global.conf':
    owner   => 'root',
    group   => 'root',
    mode    => '0600',
    content => template('rsyslog/pre_logging.conf.erb'),
    require => File['/etc/rsyslog.simp.d/00_simp_pre_logging'],
    notify  => Service['rsyslog']
  }

  file { '/etc/rsyslog.simp.d/05_simp_templates/default.conf':
    owner   => 'root',
    group   => 'root',
    mode    => '0600',
    content => template('rsyslog/templates.conf.erb'),
    require => File['/etc/rsyslog.simp.d/05_simp_templates'],
    notify  => Service['rsyslog']
  }

  file { '/etc/rsyslog.simp.d/99_simp_local/default.conf':
    owner   => 'root',
    group   => 'root',
    mode    => '0600',
    content => template('rsyslog/local.conf.erb'),
    require => File['/etc/rsyslog.simp.d/99_simp_local'],
    notify  => Service['rsyslog']
  }

  # Set the maximum number of open files in the init script.
  init_ulimit { 'mod_open_files_rsyslog':
    target      => 'rsyslog',
    item        => 'max_open_files',
    value       => $ulimit_max_open_files,
    notify      => Service['rsyslog']
  }

  # This is blocked two other places, adding this to tcpwrappers is a bit
  # overkill and prone to strange errors.
  if $tcpserver {
    tcpwrappers::allow { 'syslog':
      pattern => 'ALL'
    }
  }
  if $tls_tcpserver {
    tcpwrappers::allow { 'syslog_tls':
      pattern => 'ALL'
    }
  }

  if $use_tls or $tls_tcpserver {
    package { 'rsyslog-gnutls':
      ensure => 'latest',
      notify => Service['rsyslog']
    }

    if $use_simp_pki {
      include 'pki'

      ::pki::copy { '/etc/rsyslog.d':
        notify  => Service['rsyslog']
      }
    }
    else {
      file { '/etc/rsyslog.d/pki':
        ensure => 'directory',
        owner  => 'root',
        group  => 'root',
        mode   => '0640',
        source => $cert_source,
        notify => Service['rsyslog']
      }
    }
  }

  validate_array_member($preserveFQDN,['on','off'])
  validate_integer($system_log_rate_limit_interval)
  validate_integer($system_log_rate_limit_burst)
  validate_array_member($mainMsgQueueType,['LinkedList','FixedArray'])
  validate_string($mainMsgQueueFilename)
  if !empty($mainMsgQueueSize) { validate_integer($mainMsgQueueSize) }
  if !empty($mainMsgQueueHighWatermark) { validate_integer($mainMsgQueueHighWatermark) }
  if !empty($mainMsgQueueLowWatermark) { validate_integer($mainMsgQueueLowWatermark) }
  if !empty($mainMsgQueueDiscardmark) { validate_integer($mainMsgQueueDiscardmark) }
  if !empty($mainMsgQueueWorkerThreadMinimumMessages) { validate_integer($mainMsgQueueWorkerThreadMinimumMessages) }
  if !empty($mainMsgQueueWorkerThreads) { validate_integer($mainMsgQueueWorkerThreads) }
  validate_integer($mainMsgQueueWorkerTimeoutThreadShutdown)
  validate_integer($mainMsgQueueTimeoutEnqueue)
  validate_integer($mainMsgQueueDequeueSlowdown)
  validate_array_member($mainMsgQueueSaveOnShutdown,['on','off'])
  if !empty($mainMsgQueueMaxDiskSpace) { validate_re($mainMsgQueueMaxDiskSpace,'^\d+[KMGTP]?$') }
  validate_integer($mainMsgQueueMaxFileSize)
  validate_integer($actionResumeInterval)
  validate_integer($actionResumeRetryCount)
  validate_net_list(flatten($tcpAllowedSender))
  validate_umask($dirCreateMode)
  validate_array_member($dropMsgsWithMaliciousDnsPTRRecords,['on','off'])
  validate_array_member($escapeControlCharactersOnReceive,['on','off'])
  validate_umask($fileCreateMode)
  validate_absolute_path($include_config)
  validate_array_member($repeatedMsgReduction,['on','off'])
  validate_absolute_path($workDirectory)
  validate_integer($interval)
  validate_bool($tcpserver)
  validate_port($tcpServerRun)
  validate_bool($use_tls)
  validate_bool($tls_tcpserver)
  validate_port($tls_tcpServerRun)
  validate_integer($tls_tcpMaxSessions)
  validate_array($tls_inputTCPServerStreamDriverPermittedPeers)
  validate_bool($use_simp_pki)
  if !empty($cert_source) { validate_string($cert_source) }
  validate_absolute_path($defaultNetStreamDriverCAFile)
  validate_absolute_path($defaultNetStreamDriverCertFile)
  validate_absolute_path($defaultNetStreamDriverKeyFile)
  validate_array($actionSendStreamDriverPermittedPeers)
  validate_string($actionSendStreamDriverAuthMode)
  validate_bool($udpserver)
  validate_net_list($udpServerAddress)
  validate_port($udpServerRun)
  validate_net_list(flatten($udpAllowedSender))
  validate_umask($umask)
  validate_re($ulimit_max_open_files,'^(unlimited|[0-9]*)$')
  validate_integer($compat_mode)
  validate_bool($suppress_noauth_warn)
  validate_bool($disable_remote_dns)
  validate_bool($include_rsyslog_d)
  validate_bool($enable_default_rules)
  validate_bool($allow_failover)
}
