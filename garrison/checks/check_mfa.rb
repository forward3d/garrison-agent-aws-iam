module Garrison
  module Checks
    class CheckMfa < Check

      def settings
        self.source ||= 'aws-iam'
        self.severity ||= 'high'
        self.family ||= 'infrastructure'
        self.type ||= 'compliance'
      end

      def key_values
        [
          { key: 'datacenter', value: 'aws' },
          { key: 'aws-service', value: 'iam' },
          { key: 'aws-account', value: AwsHelper.whoami.account }
        ]
      end

      def perform
        iam = Aws::IAM::Client.new
        AwsHelper.list_iam_users(iam).each do |user|
          mfa_devices = iam.list_mfa_devices user_name: user.user_name
          next if mfa_devices.mfa_devices.count > 0

          alert(
            name: 'IAM User MFA Violation',
            target: user.arn,
            detail: 'no mfa devices found',
            finding: user.to_h.merge(mfa_devices.to_h).to_json,
            no_repeat: false,
            finding_id: "aws-iam-#{AwsHelper.whoami.account}-mfa-#{user.user_name}",
            urls: [
              {
                name: 'AWS Dashboard',
                url: "https://console.aws.amazon.com/iam/home#/users/#{user.user_name}"
              }
            ],
            key_values: []
          )
        end

      end

    end
  end
end
