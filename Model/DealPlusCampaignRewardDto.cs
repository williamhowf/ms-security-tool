namespace ResidentialSecurity.Model
{
    public class DealPlusCampaignRewardDto
    {
        public DealPlusCampaignRewardDto()
        {
            Type = "string";
            TrxID = "string";
            TrxDateTime = "yyyy-MM-ddTHH:mm:ss.fffZ";
            GlobalGuid = "string";
            AmountCny = 0M;
            AmountUsd = 0M;
            AmountMbtc = 0M;
            CnyToMbtcRate = 0M;
            UsdToMbtcRate = 0M;
            UplineAmountCny = 0M;
            UplineAmountUsd = 0M;
            UplineAmountMbtc = 0M;
        }

        public string Type { get; set; }
        public string TrxID { get; set; }
        public string TrxDateTime { get; set; }
        public string GlobalGuid { get; set; }
        public decimal AmountCny { get; set; }
        public decimal AmountUsd { get; set; }
        public decimal AmountMbtc { get; set; }
        public decimal CnyToMbtcRate { get; set; }
        public decimal UsdToMbtcRate { get; set; }
        public decimal UplineAmountCny { get; set; }
        public decimal UplineAmountUsd { get; set; }
        public decimal UplineAmountMbtc { get; set; }
    }
}
