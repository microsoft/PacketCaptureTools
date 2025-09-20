// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.PacketCapture.Analyzer.Packet.Network.ARP
{
    /// <summary>
    /// Address Resolution Protocol operation codes.
    /// </summary>
    public enum OperationCode
    {
        /// <summary>
        /// Lower-bound reserved value.
        /// </summary>
        ReservedLow = 0,

        /// <summary>
        /// Request operation value.
        /// </summary>
        Request = 1,

        /// <summary>
        /// Reply operation value.
        /// </summary>
        Reply = 2,

        /// <summary>
        /// Request reverse operation value.
        /// </summary>
        RequestReverse = 3,

        /// <summary>
        /// Reply reverse operation value.
        /// </summary>
        ReplyReverse = 4,

        /// <summary>
        /// DRARP request operation value.
        /// </summary>
        DRARP_Request = 5,

        /// <summary>
        /// DRAP reply operation value.
        /// </summary>
        DRARP_Reply = 6,

        /// <summary>
        /// DRARP error operation value.
        /// </summary>
        DRARP_Error = 7,

        /// <summary>
        /// INARP request operation value.
        /// </summary>
        INARP_Request = 8,

        /// <summary>
        /// INARP reply operation value.
        /// </summary>
        INARP_Reply = 9,

        /// <summary>
        /// ARP-NAK operation value.
        /// </summary>
        ARP_NAK = 10,

        /// <summary>
        /// MARS-Request operation value.
        /// </summary>
        MARS_Request = 11,

        /// <summary>
        /// MARS-Multi operation value.
        /// </summary>
        MARS_Multi = 12,

        /// <summary>
        /// MARS-MServ operation value.
        /// </summary>
        MARS_MServ = 13,

        /// <summary>
        /// MARS-Join operation value.
        /// </summary>
        MARS_Join = 14,

        /// <summary>
        /// MARS-Leave operation value.
        /// </summary>
        MARS_Leave = 15,

        /// <summary>
        /// MARS-NAK operation value.
        /// </summary>
        MARS_NAK = 16,

        /// <summary>
        /// MARS-Unserv operation value.
        /// </summary>
        MARS_Unserv = 17,

        /// <summary>
        /// MARS-SJoin operation value.
        /// </summary>
        MARS_SJoin = 18,

        /// <summary>
        /// MARS-SLeave operation value.
        /// </summary>
        MARS_SLeave = 19,

        /// <summary>
        /// MARS-Grouplist Request operation value.
        /// </summary>
        MARS_GroupList_Request = 20,

        /// <summary>
        /// MARS-Grouplist Reply operation value.
        /// </summary>
        MARS_GroupList_Reply = 21,

        /// <summary>
        /// MARS-Redirect Map operation value.
        /// </summary>
        MARS_Redirect_Map = 22,

        /// <summary>
        /// MAPOS-UNARP operation value.
        /// </summary>
        MAPOS_UNARP = 23,

        /// <summary>
        /// OP_EXP1 operation value.
        /// </summary>
        OP_EXP1 = 24,

        /// <summary>
        /// OP_EXP2 operation value.
        /// </summary>
        OP_EXP2 = 25,

        /// <summary>
        /// Reserved upper-bound value.
        /// </summary>
        ReservedHigh = 65535,
    }
}
