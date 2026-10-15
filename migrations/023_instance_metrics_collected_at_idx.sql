-- 七天指标清理按采样时间过滤，独立时间索引避免扫描全部实例主键。
CREATE INDEX IF NOT EXISTS instance_metrics_collected_at_idx ON instance_metrics(collected_at);
