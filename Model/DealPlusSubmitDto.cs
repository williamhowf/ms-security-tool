namespace ResidentialSecurity.Model
{
    public class DealPlusSubmitDto
    {
        public DealPlusSubmitDto()
        {
            TrxID = "string";
            TrxDateTime = "yyyy-MM-ddTHH:mm:ss.fffZ";
            Merchant = new Merchant
            {
                ID = "string GlobalGuid",
                Name = "string",
                UsdToMbtcRate = 0M,
                RefUsdAmt = 0.0M,
                CnyToMbtcRate = 0M,
                RefCnyAmt = 0.0M,
                RefMbtcAmt = 0.0M
            };
        }

        public string TrxID { get; set; }
        public string TrxDateTime { get; set; }
        public Merchant Merchant { get; set; }
    }

    public class Merchant
    {
        public string ID { get; set; }
        public string Name { get; set; }
        public decimal RefMbtcAmt { get; set; }
        public decimal RefUsdAmt { get; set; }
        public decimal UsdToMbtcRate { get; set; }
        public decimal RefCnyAmt { get; set; }
        public decimal CnyToMbtcRate { get; set; }
    }
}
