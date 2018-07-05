module Garrison
  module Checks
    class CheckUnused < Check

      def settings
        self.source ||= 'aws-iam'
        self.severity ||= 'medium'
        self.family ||= 'infrastructure'
        self.type ||= 'compliance'
        self.options[:threshold] ||= 90
      end

      def key_values
        [
          { key: 'datacenter', value: 'aws' },
          { key: 'aws-service', value: 'iam' },
          { key: 'aws-account', value: AwsHelper.whoami.account }
        ]
      end

      def perform
        iam = Aws::IAM::Client.new(region: 'us-east-1')
        AwsHelper.list_iam_users(iam).each do |user|
          access_keys = iam.list_access_keys user_name: user.user_name
          active_keys = access_keys.access_key_metadata.select { |ak| ak.status == 'Active' }

          active_keys.map! do |access_key|
            last_used = iam.get_access_key_last_used access_key_id: access_key.access_key_id

            # this hardcoded date is when IAM access key tracking started
            # if a key has not been used after that, the api returns nil
            date_used = last_used.access_key_last_used.last_used_date || Date.parse('2015-04-22')

            {
              last_used: date_used,
              days_since: (Date.today - date_used.to_date).to_i,
              user: user.to_h,
              access_key: access_key.to_h
            }
          end

          active_keys.select { |ak| ak[:days_since] > options[:threshold].to_i }.each do |key|
            alert(
              name: 'IAM Unused Access Key',
              target: key[:user][:arn],
              detail: "last_used: #{key[:last_used]} (>#{options[:threshold]} days)",
              finding: key.to_json,
              no_repeat: true,
              finding_id: "aws-iam-#{AwsHelper.whoami.account}-unused-#{key[:user][:user_id]}",
              urls: [
                {
                  name: 'AWS Dashboard',
                  url: "https://console.aws.amazon.com/iam/home#/users/#{key[:user][:user_name]}?section=security_credentials"
                }
              ],
              key_values: []
            )
          end
        end

      end

    end
  end
end
