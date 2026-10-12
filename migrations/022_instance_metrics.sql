-- Agent 每分钟上报一次托管实例运行指标；保留原始分钟点，前端按最近 24 小时展示。
CREATE TABLE instance_metrics (
  instance_id uuid NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
  collected_at timestamptz NOT NULL,
  cpu_usage_percent double precision CHECK(cpu_usage_percent BETWEEN 0 AND 100),
  memory_usage_mb integer CHECK(memory_usage_mb >= 0),
  memory_metric_source text NOT NULL DEFAULT '',
  PRIMARY KEY(instance_id,collected_at)
);
CREATE INDEX instance_metrics_recent_idx ON instance_metrics(instance_id,collected_at DESC);
