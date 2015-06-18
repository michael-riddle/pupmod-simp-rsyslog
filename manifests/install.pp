class rsyslog::install {

  # This is where the custom rules will go. They will be purged if not
  # managed!
  file { '/etc/rsyslog.simp.d':
    ensure  => 'directory',
    owner   => 'root',
    group   => 'root',
    recurse => true,
    purge   => true,
    force   => true,
    mode    => '0700',
    require => Package["rsyslog.$::hardwaremodel"]
  }

  file { ['/etc/rsyslog.simp.d/00_simp_pre_logging','/etc/rsyslog.simp.d/05_simp_templates','/etc/rsyslog.simp.d/06_simp_drop_rules','/etc/rsyslog.simp.d/10_simp_remote', '/etc/rsyslog.simp.d/99_simp_local']:
    ensure  => 'directory',
    owner   => 'root',
    group   => 'root',
    mode    => '0700',
    recurse => true,
    purge   => true,
    require => [File['/etc/rsyslog.simp.d'], Package["rsyslog.$::hardwaremodel"]]
  }

  file { '/etc/rsyslog.d':
    ensure  => 'directory',
    owner   => 'root',
    group   => 'root',
    mode    => '0700',
    require => Package["rsyslog.$::hardwaremodel"]
  }

  file { '/etc/rsyslog.d/README.conf':
    ensure  => 'present',
    owner   => 'root',
    group   => 'root',
    mode    => '0700',
    content =>
      "# Place .conf files that rsyslog should process into this directory.\n"
  }

  file { '/var/spool/rsyslog':
    ensure  => 'directory',
    owner   => 'root',
    group   => 'root',
    mode    => '0700',
    require => Package["rsyslog.$::hardwaremodel"]
  }

  package { "rsyslog.${::hardwaremodel}": ensure => 'latest' }

  # Some hackery to remove the i386 version of rsyslog if you're on a x86_64
  # system.
  if $::hardwaremodel == 'x86_64' {
    package { 'rsyslog.i386':
      ensure => 'absent',
      notify => Package["rsyslog.$::hardwaremodel"]
    }
  }
}
