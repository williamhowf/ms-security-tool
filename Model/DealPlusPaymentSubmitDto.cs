namespace ResidentialSecurity.Model
{
    public class DealPlusPaymentSubmitDto
    {
        public DealPlusPaymentSubmitDto()
        {
            OrderID = "string";
            OrderDateTime = "yyyy-MM-ddTHH:mm:ss.fffZ";
            GlobalGuid = "string";
            UsdRateId = 0;
            UsdToMbtcRate = 0M;
            AmountUsd = 0M;
            CnyRateId = 0;
            CnyToMbtcRate = 0M;
            AmountCny = 0M;
            AmountMbtc = 0M;
        }

        public string OrderID { get; set; }
        public string OrderDateTime { get; set; }
        public string GlobalGuid { get; set; }
        public int UsdRateId { get; set; }
        public decimal UsdToMbtcRate { get; set; }
        public decimal AmountUsd { get; set; }
        public int CnyRateId { get; set; }
        public decimal CnyToMbtcRate { get; set; }
        public decimal AmountCny { get; set; }
        public decimal AmountMbtc { get; set; }
    }
}
