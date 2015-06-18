class rsyslog::service{

  include 'rsyslog::config'

  service { 'rsyslog':
    ensure     => 'running',
    enable     => true,
    binary     => '/usr/bin/rsyslog',
    hasrestart => true,
    hasstatus  => true,
    require    => [
      File['/etc/rsyslog.conf'],
      Package["rsyslog.$::hardwaremodel"]
    ]
  }

}
