using System.Collections.Generic;

namespace ResidentialSecurity.Model.Base
{
    public class BaseRetrieveListTransactionIDs
    {
        public BaseRetrieveListTransactionIDs()
        {
            TrxIDs = new List<string>() { "string", "string" };
        }

        public IList<string> TrxIDs { get; set; }
    }
}
