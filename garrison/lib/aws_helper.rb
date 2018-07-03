module Garrison
  class AwsHelper

    def self.whoami
      @whoami ||= Aws::STS::Client.new(region: 'us-east-1').get_caller_identity
    end

    def self.all_regions
      Aws.partition('aws').regions.map(&:name)
    end

    def self.list_iam_users(iam)
      Enumerator.new do |yielder|
        marker = ''

        loop do
          Logging.debug "AWS SDK - Listings Users (marker=#{marker})"
          params = {}
          params[:marker] = marker if marker != ''
          results = iam.list_users(params)
          results.users.map { |item| yielder << item }

          if results.marker
            marker = results.marker
          else
            raise StopIteration
          end
        end
      end.lazy
    end

  end
end
