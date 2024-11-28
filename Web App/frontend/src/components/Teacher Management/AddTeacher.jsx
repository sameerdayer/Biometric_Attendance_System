import React, { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import axios from "axios";
import { IoIosArrowForward } from "react-icons/io";
import { useSidebar } from "../../context/SidebarContext";
import Header from "../Common/Header";
import Navbar from "../Common/Navbar";

const AddTeacher = () => {
  const { isSidebarVisible, toggleSidebar } = useSidebar();

  const [formData, setFormData] = useState({
    name: "",
    teacherID: "",
    designation: "",
    department: "",
    subject: "",
    experience: "",
    contact: "",
    email: "",
    office: "",
    qualifications: "",
    address: "",
  });

  const [error, setError] = useState("");
  const navigate = useNavigate();

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData({ ...formData, [name]: value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const response = await axios.post(
        "http://127.0.0.1:3001/api/teacher/add-teacher",
        formData
      );
      console.log(response.data);
      alert("Teacher added successfully!");
      navigate("/teacher-management");
    } catch (err) {
      console.error("Error adding teacher:", err.response?.data || err.message);
      setError("Failed to add teacher. Please try again.");
    }
  };

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
              <h1>Add Teacher</h1>
            </div>
            {/* Breadcrumb */}
            <div className="breadcrumb">
              <Link to="/dashboard">Home</Link>
              <span>
                <IoIosArrowForward className="breadcrumb-icon" />
              </span>
              <Link to="/teacher-management">Teacher Management</Link>
              <span>
                <IoIosArrowForward className="breadcrumb-icon" />
              </span>
              <span className="current-breadcrumb">Add Teacher</span>
            </div>
          </section>
          <section className="explore-details">
            <div className="min-h-screen bg-gray-100 py-10">
              <div className="container mx-auto px-4">
                <form
                  onSubmit={handleSubmit}
                  className="bg-white shadow-lg rounded-lg p-6 max-w-2xl mx-auto"
                >
                  {error && <p className="text-red-500 mb-4">{error}</p>}

                  {/* Form Fields */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-600">
                        Name
                        <input
                          type="text"
                          name="name"
                          value={formData.name}
                          onChange={handleInputChange}
                          required
                          className="w-full px-3 py-2 border rounded focus:ring focus:outline-none"
                        />
                      </label>
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-600">
                        Teacher ID
                        <input
                          type="text"
                          name="teacherID"
                          value={formData.teacherID}
                          onChange={handleInputChange}
                          required
                          className="w-full px-3 py-2 border rounded focus:ring focus:outline-none"
                        />
                      </label>
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-600">
                        Designation
                        <input
                          type="text"
                          name="designation"
                          value={formData.designation}
                          onChange={handleInputChange}
                          className="w-full px-3 py-2 border rounded focus:ring focus:outline-none"
                        />
                      </label>
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-600">
                        Department
                        <input
                          type="text"
                          name="department"
                          value={formData.department}
                          onChange={handleInputChange}
                          className="w-full px-3 py-2 border rounded focus:ring focus:outline-none"
                        />
                      </label>
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-600">
                        Subjects
                        <input
                          type="text"
                          name="subject"
                          value={formData.subject}
                          onChange={handleInputChange}
                          required
                          placeholder="Comma-separated values"
                          className="w-full px-3 py-2 border rounded focus:ring focus:outline-none"
                        />
                      </label>
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-600">
                        Experience
                        <input
                          type="number"
                          name="experience"
                          value={formData.experience}
                          onChange={handleInputChange}
                          className="w-full px-3 py-2 border rounded focus:ring focus:outline-none"
                        />
                      </label>
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-600">
                        Contact
                        <input
                          type="number"
                          name="contact"
                          value={formData.contact}
                          onChange={handleInputChange}
                          required
                          className="w-full px-3 py-2 border rounded focus:ring focus:outline-none"
                        />
                      </label>
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-600">
                        Email
                        <input
                          type="email"
                          name="email"
                          value={formData.email}
                          onChange={handleInputChange}
                          className="w-full px-3 py-2 border rounded focus:ring focus:outline-none"
                        />
                      </label>
                    </div>

                    <div className="md:col-span-2">
                      <label className="block text-sm font-medium text-gray-600">
                        Office Location
                        <input
                          type="text"
                          name="office"
                          value={formData.office}
                          onChange={handleInputChange}
                          className="w-full px-3 py-2 border rounded focus:ring focus:outline-none"
                        />
                      </label>
                    </div>

                    <div className="md:col-span-2">
                      <label className="block text-sm font-medium text-gray-600">
                        Qualifications
                        <input
                          type="text"
                          name="qualifications"
                          value={formData.qualifications}
                          onChange={handleInputChange}
                          className="w-full px-3 py-2 border rounded focus:ring focus:outline-none"
                        />
                      </label>
                    </div>

                    <div className="md:col-span-2">
                      <label className="block text-sm font-medium text-gray-600">
                        Address
                        <textarea
                          name="address"
                          value={formData.address}
                          onChange={handleInputChange}
                          className="w-full px-3 py-2 border rounded focus:ring focus:outline-none"
                        ></textarea>
                      </label>
                    </div>
                  </div>

                  {/* Buttons */}
                  <div className="flex justify-between mt-6">
                    <button
                      type="button"
                      onClick={() => navigate("/teacher-management")}
                      className="bg-red-500 text-white px-4 py-2 text-nowrap rounded hover:bg-red-600"
                    >
                      Cancel
                    </button>
                    <button
                      type="submit"
                      className="bg-blue-500 text-white px-4 py-2 text-nowrap rounded hover:bg-blue-600"
                    >
                      Add Teacher
                    </button>
                  </div>
                </form>
              </div>
            </div>
          </section>
        </main>
      </div>
      {/* Add Teacher Form */}
    </>
  );
};

export default AddTeacher;