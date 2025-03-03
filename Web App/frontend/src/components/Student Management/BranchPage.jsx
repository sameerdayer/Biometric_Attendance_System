import React, { useEffect, useState } from "react";
import Navbar from "../Common/Navbar";
import Header from "../Common/Header";
import {
  Link,
  replace,
  useLocation,
  useNavigate,
  useParams,
} from "react-router-dom";
import { useSidebar } from "../../context/SidebarContext";
import { IoIosArrowForward } from "../../utils/icons";
import axios from "axios";
import Loading from "../Common/Loading";
import ErrorBox from "../Common/ErrorBox";
import {
  changeBranchFormatFnx,
  changeYearFormatFnx,
} from "../../utils/helpers";

const BranchPage = () => {
  const { isSidebarVisible, toggleSidebar } = useSidebar();
  const { year, branch } = useParams();
  const navigate = useNavigate();
  const { state } = useLocation();
  const [studentData, setStudentData] = useState([]);
  const [filters, setFilters] = useState({
    searchQuery: "",
  });
  const [errorMessage, setErrorMessage] = useState([{ isActive: false }]);

  const handleChildError = (type, message) => {
    setErrorMessage(() => [
      {
        id: Math.random(),
        type: type,
        message: message,
        isActive: true,
      },
    ]);
  };

  const updateFilter = (e) => {
    const { name, value } = e.target;
    setFilters((prev) => ({ ...prev, [name]: value }));
  };

  const fetchStudentsByYear = async (year, branch) => {
    try {
      const response = await axios.get(
        `${import.meta.env.VITE_API_BASE_URL}student/${year}/${branch}`,
        { params: filters }
      );

      if (response.data.row && response.data.row.length > 0) {
        setStudentData(response.data.row);
      } else {
        setStudentData([]);
      }
    } catch (error) {
      setStudentData([]);

      handleChildError(
        "error",
        error.response?.data.error || "Failed to fetch data. Please try again."
      );
    }
  };

  useEffect(() => {
    fetchStudentsByYear(year, branch);
  }, [year, branch, filters]);

  useEffect(() => {
    if (state && state.error) {
      handleChildError(state.error, state.message);
      navigate("", { replace: true, state: null });
    }
  }, [state]);

  const changeYearFormat = changeYearFormatFnx(year);
  const changeBranchFormat = changeBranchFormatFnx(branch);

  return (
    <>
      <Header toggleSidebar={toggleSidebar} />

      <Navbar isSidebarVisible={isSidebarVisible} />
      <div
        className={`content-wrapper ${isSidebarVisible ? "" : "full-width"}`}
      >
        <main>
          <section className="page-header">
            <div className="header-title">
              <h1>Branch: {changeBranchFormat}</h1>
              <div className="flex gap-2 items-center">
                <button
                  onClick={() => {
                    navigate(`/${year}/${branch}/add-student`);
                  }}
                  className="bg-blue-500 text-white px-4 py-2 rounded-md hover:bg-blue-600"
                >
                  Add Student
                </button>
              </div>
            </div>
            {/* Breadcrumb */}
            <div className="breadcrumb">
              <Link to="/dashboard">Home</Link>
              <span>
                <IoIosArrowForward className="breadcrumb-icon" />
              </span>
              <Link to={`/${year}`} onClick={(e) => e.stopPropagation()}>
                {changeYearFormat}
              </Link>
              <span>
                <IoIosArrowForward className="breadcrumb-icon" />
              </span>
              <span className="current-breadcrumb">{changeBranchFormat}</span>
            </div>
            <div className="flex justify-between gap-4 my-4">
              <input
                type="text"
                name="searchQuery"
                value={filters.searchQuery}
                onChange={updateFilter}
                placeholder="Search by name"
                className="border border-gray-300 rounded-md px-4 py-2 w-full sm:w-1/3"
              />

              <button
                onClick={() => {
                  setFilters({
                    searchQuery: "",
                  });
                }}
                className="bg-red-500 text-white px-4 py-2 text-nowrap rounded-md hover:bg-red-600"
              >
                Reset
              </button>
            </div>
            {errorMessage[0].isActive &&
              errorMessage.map((errorMessage) => (
                <ErrorBox
                  key={errorMessage.id}
                  type={errorMessage.type}
                  message={errorMessage.message}
                  onClose={() => {
                    setErrorMessage([{ isActive: false }]);
                  }}
                />
              ))}
          </section>

          {studentData ? (
            <section className="explore-details">
              <div className="explore-header">
                <h2 className="explore-head-title">Student Details</h2>
                <p className="explore-head-description">
                  Select your student to explore details.
                </p>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6 p-4">
                {studentData.map((student) => (
                  <div
                    key={student.StudentID}
                    className="bg-white shadow-md rounded-lg p-4 transform transition-transform ease-in-out delay-0  hover:scale-105 hover:shadow-lg"
                  >
                    <h3 className="text-xl font-bold mb-2">
                      {student.StudentName}
                    </h3>
                    <p className="text-gray-600">
                      Enrollment: {student.EnrollmentNo}
                    </p>
                    <p className="text-gray-600">Branch: {student.Branch}</p>
                    <p className="text-gray-600">Batch: {student.Batch}</p>
                    <div className="flex s-between items-center mb-4">
                      <p className="text-gray-600">
                        Year:{" "}
                        <span className="font-semibold">
                          {`${student.Year}${
                            student.Year === 1
                              ? "st"
                              : student.Year === 2
                              ? "nd"
                              : student.Year === 3
                              ? "rd"
                              : "th"
                          }`}
                        </span>
                      </p>
                      <p className="text-gray-600">
                        Semester:{" "}
                        <span className="font-semibold">
                          {`${student.Semester}${
                            student.Semester === 1
                              ? "st"
                              : student.Semester === 2
                              ? "nd"
                              : student.Semester === 3
                              ? "rd"
                              : "th"
                          }`}
                        </span>
                      </p>
                    </div>
                    <p className="text-gray-600">
                      Attendance:{" "}
                      <span className="text-green-600 font-bold">
                        {student.attendance}%
                      </span>
                    </p>
                    <button
                      onClick={() => navigate(student.studentPath)}
                      className="mt-4 bg-blue-500 text-white py-2 px-4 rounded hover:bg-blue-600"
                    >
                      More Details
                    </button>
                  </div>
                ))}
              </div>
              {/* Another Card Format */}
              {/* <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6 p-6">
              <div className="bg-white shadow-md rounded-lg overflow-hidden hover:shadow-lg transition-shadow duration-300">
                <div className="p-6">
                  <div className="text-lg font-semibold mb-2">
                    Name: <span className="text-gray-700">John Doe</span>
                  </div>
                  <div className="text-gray-600 mb-2">
                    Enrollment: <span className="font-medium">123456</span>
                  </div>
                  <div className="text-gray-600 mb-2">
                    Branch: <span className="font-medium">CSE</span>
                  </div>
                  <div className="flex justify-between items-center mb-4">
                    <div className="text-gray-600">
                      Year: <span className="font-medium">3rd</span>
                    </div>
                    <div className="text-gray-600">
                      Sem: <span className="font-medium">5th</span>
                    </div>
                  </div>
                  <div className="text-gray-600 mb-4">
                    Attendance Rate:{" "}
                    <span className="font-medium text-green-500">85%</span>
                  </div>
                  <button className="w-full bg-blue-500 text-white py-2 rounded-md hover:bg-blue-600 transition duration-300">
                    More Details
                  </button>
                </div>
              </div>

              <div className="bg-white shadow-md rounded-lg overflow-hidden hover:shadow-lg transition-shadow duration-300">
                <div className="p-6">
                  <div className="text-lg font-semibold mb-2">
                    Name: <span className="text-gray-700">Jane Smith</span>
                  </div>
                  <div className="text-gray-600 mb-2">
                    Enrollment: <span className="font-medium">789012</span>
                  </div>
                  <div className="text-gray-600 mb-2">
                    Branch: <span className="font-medium">ECE</span>
                  </div>
                  <div className="flex justify-between items-center mb-4">
                    <div className="text-gray-600">
                      Year: <span className="font-medium">2nd</span>
                    </div>
                    <div className="text-gray-600">
                      Sem: <span className="font-medium">3rd</span>
                    </div>
                  </div>
                  <div className="text-gray-600 mb-4">
                    Attendance Rate:{" "}
                    <span className="font-medium text-green-500">92%</span>
                  </div>
                  <button className="w-full bg-blue-500 text-white py-2 rounded-md hover:bg-blue-600 transition duration-300">
                    More Details
                  </button>
                </div>
              </div>
            </div> */}
            </section>
          ) : (
            <Loading />
          )}
        </main>
      </div>
    </>
  );
};

export default BranchPage;
