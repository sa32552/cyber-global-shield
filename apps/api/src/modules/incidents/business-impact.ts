import { env } from "../../config/env";

export const estimateBusinessLoss = (failedRequests: number, avgOrderValue?: number, conversionRate?: number) => {
  const averageOrder = avgOrderValue ?? env.DEFAULT_AVG_ORDER_VALUE;
  const conversion = conversionRate ?? env.DEFAULT_CONVERSION_RATE;
  return Number((failedRequests * averageOrder * conversion).toFixed(2));
};