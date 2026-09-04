# frozen_string_literal: true

module ::ProxyTracerBlocker
  class AdminProxyTracerController < ::Admin::AdminController
    skip_before_action :check_proxytracer_global_access, raise: false
    before_action :ensure_admin

    def logs
      Rails.logger.debug("[ProxyTracer] Admin requested blocked logs from #{request.remote_ip} (User: #{current_user&.username})")
      raw_logs = begin
        Discourse.redis.lrange("proxytracer:logs", 0, 499) || []
      rescue StandardError => e
        Rails.logger.error("[ProxyTracer] Redis logs fetch failed: #{e.class}: #{e.message}")
        []
      end

      logs = raw_logs.filter_map do |entry|
        begin
          JSON.parse(entry)
        rescue JSON::ParserError
          nil
        end
      end
      Rails.logger.debug("[ProxyTracer] Returning #{logs.size} log entries")
      render_json_dump(logs: logs)
    rescue StandardError => e
      Rails.logger.error("[ProxyTracer] Admin Logs Controller Error: #{e.class}: #{e.message}\n#{e.backtrace&.first(10)&.join("\n")}")
      render json: { error: "#{e.class}: #{e.message}" }, status: :internal_server_error
    end

    def stats
      Rails.logger.debug("[ProxyTracer] Admin requested stats from #{request.remote_ip} (User: #{current_user&.username})")
      days = (0..29).map { |i| (Date.current - i).iso8601 }.reverse
      keys = days.flat_map { |day| ["proxytracer:stats:#{day}:requests", "proxytracer:stats:#{day}:detections"] }
      values = begin
        Discourse.redis.mget(*keys) || []
      rescue StandardError => e1
        Rails.logger.debug("[ProxyTracer] Redis mget failed (#{e1.message}), trying pipelined fallback")
        begin
          Discourse.redis.pipelined do |pipeline|
            keys.each { |k| pipeline.get(k) }
          end || []
        rescue StandardError => e2
          Rails.logger.error("[ProxyTracer] Redis stats pipelined fetch failed: #{e2.class}: #{e2.message}")
          []
        end
      end

      stats_data = days.each_with_index.map do |day, idx|
        {
          date: day,
          requests: values[idx * 2].to_i,
          detections: values[idx * 2 + 1].to_i
        }
      end
      total_req = stats_data.sum { |s| s[:requests] }
      total_det = stats_data.sum { |s| s[:detections] }
      Rails.logger.debug("[ProxyTracer] Returning #{stats_data.size} days of stats (Total checks: #{total_req}, Detections: #{total_det})")
      render_json_dump(stats: stats_data)
    rescue StandardError => e
      Rails.logger.error("[ProxyTracer] Admin Stats Controller Error: #{e.class}: #{e.message}\n#{e.backtrace&.first(10)&.join("\n")}")
      render json: { error: "#{e.class}: #{e.message}" }, status: :internal_server_error
    end
  end
end
